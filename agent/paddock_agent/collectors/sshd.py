"""sshd collector: effective OpenSSH server configuration (Python 3.8 syntax only).

Source of truth is ``sshd -T`` (run as root) plus a probe matrix of
``sshd -T -C user=U,host=probe.invalid,addr=A`` runs recorded as *deltas* against the
global result. Only allowlisted keys are kept. When ``sshd -T`` cannot run, the
collector falls back to a text parse of ``sshd_config`` and its ``Include`` files; that
result is always ``conf: approximate, source: text`` and therefore never a HOLDS.

Every parser here is a pure function over text so fixtures drive it without an OS.
"""
import fnmatch
import hashlib
import ipaddress
import os
import re
import stat

from . import base
from ..runner import FIXED_PATH
from .base import clean_str

MAIN_CONFIG = "/etc/ssh/sshd_config"
CONFIG_DIR = "/etc/ssh"
SSHD_CANDIDATES = ("/usr/sbin/sshd", "/sbin/sshd", "/usr/bin/sshd")
LOCAL_SSHD_DIRS = ("/usr/local/sbin", "/usr/local/bin")
FIXED_DIRS = tuple(FIXED_PATH.split(":"))
TRUSTED_UID = 0          # owner a binary or directory outside the fixed PATH must have
PIDFILES = ("/run/sshd.pid", "/var/run/sshd.pid")
PROBE_ADDRS = ("203.0.113.7", "10.255.255.1")
PROBE_HOST = "probe.invalid"
NONEXISTENT_USER = "paddock-nonexistent-probe"
NONEXISTENT_LABEL = "<nonexistent>"
MAX_LOGIN_USERS = 20
MAX_MATCH_USERS = 10
MAX_EXTRA_USERS = 20
MAX_PROBE_RUNS = 150
MAX_ADDR_REPS = 12
MAX_FILES = 64
MAX_INCLUDE_DEPTH = 5
MAX_FILE_BYTES = 1 << 20
MAX_LIST_ITEMS = 50
PROBE_TIMEOUT_S = 8
NOLOGIN_SHELLS = frozenset([
    "/usr/sbin/nologin", "/sbin/nologin", "/bin/false", "/usr/bin/false", "/bin/sync",
    "/sbin/halt", "/sbin/shutdown", "/usr/sbin/shutdown", "/usr/sbin/halt", "/bin/nologin",
])
# what may be passed as ``-C user=NAME``: any case (RHEL and shadow-utils allow it), no separator,
# whitespace, '@' (user@host pattern form) or a leading '-'
_USERNAME_RE = re.compile(r"^[A-Za-z0-9_][A-Za-z0-9_.$-]{0,63}$")
NSS_FILES_SOURCES = frozenset(["files", "compat", "systemd"])
USERDB_DIRS = ("/etc/userdb", "/run/userdb", "/var/lib/systemd/home")
SSH_NAME_HINTS = ("ssh", "dropbear")
# Programs known NOT to be (or front) an SSH server. A public TCP listener of any other program, or of
# none we can attribute, keeps "no SSH server" unproven: tool_missing needs every such listener here.
# Deliberately short: web servers and proxies (nginx, haproxy, envoy, docker-proxy, rootlessport,
# kube-proxy, socat, ...) can forward port 2222 to an SSH server, and gitea/teleport/sftpgo are SSH servers.
NON_SSH_COMMS = frozenset([
    "postgres", "postmaster", "mysqld", "mariadbd", "mongod", "redis-server", "valkey-server",
    "memcached", "named", "unbound", "dnsmasq", "chronyd", "ntpd", "cupsd", "smbd", "nmbd",
    "master", "dovecot", "exim4", "cockroach",
])

BOOL_KEYS = frozenset([
    "passwordauthentication", "kbdinteractiveauthentication", "pubkeyauthentication",
    "permitemptypasswords", "usepam", "x11forwarding", "permituserenvironment",
    "hostbasedauthentication", "gssapiauthentication", "strictmodes",
])
ENUM_KEYS = {
    "permitrootlogin": frozenset(["yes", "no", "prohibit-password", "forced-commands-only"]),
    "addressfamily": frozenset(["any", "inet", "inet6"]),
    "allowtcpforwarding": frozenset(["yes", "no", "all", "local", "remote"]),
    "loglevel": frozenset(["quiet", "fatal", "error", "info", "verbose", "debug", "debug1",
                           "debug2", "debug3"]),
}
INT_KEYS = frozenset(["maxauthtries", "logingracetime", "maxsessions"])
STR_KEYS = frozenset(["authenticationmethods"])
LIST_INT_KEYS = frozenset(["port"])
LIST_STR_LOWER_KEYS = frozenset(["listenaddress"])
LIST_NAME_KEYS = frozenset(["allowusers", "allowgroups", "denyusers", "denygroups"])
LIST_TOKEN_KEYS = frozenset(["authorizedkeysfile"])
ALIASES = {"challengeresponseauthentication": "kbdinteractiveauthentication"}
# keys that accumulate across repeated lines (everything else: first value wins in text mode)
MULTI_KEYS = LIST_INT_KEYS | LIST_STR_LOWER_KEYS | LIST_NAME_KEYS | frozenset(["hostkey"])
ALLOWLIST = (BOOL_KEYS | frozenset(ENUM_KEYS) | INT_KEYS | STR_KEYS | LIST_INT_KEYS
             | LIST_STR_LOWER_KEYS | LIST_NAME_KEYS | LIST_TOKEN_KEYS
             | frozenset(["authorizedkeyscommand"]))
PROBEABLE_CRITERIA = frozenset(["all", "user", "group", "address"])
_YES = {"yes": "yes", "true": "yes", "on": "yes", "1": "yes",
        "no": "no", "false": "no", "off": "no", "0": "no"}


# ---------------------------------------------------------------- line level
def split_directive(line):
    """Split one config line into ``(keyword_lower, [args])`` or ``None`` for blank/comment."""
    s = line.strip()
    if not s or s.startswith("#"):
        return None
    m = re.match(r"([A-Za-z0-9_-]+)", s)
    if not m:
        return None
    key = m.group(1).lower()
    rest = s[m.end():]
    rest = rest.lstrip()
    if rest.startswith("="):
        rest = rest[1:]
    args = []
    cur = []
    in_q = False
    have = False
    for ch in rest:
        if in_q:
            if ch == '"':
                in_q = False
            else:
                cur.append(ch)
            continue
        if ch == '"':
            in_q = True
            have = True
        elif ch in " \t":
            if have or cur:
                args.append("".join(cur))
                cur = []
                have = False
        elif ch == "#" and not cur and not have:
            break
        else:
            cur.append(ch)
    if have or cur:
        args.append("".join(cur))
    return key, args


def parse_sshd_T(text):
    """Parse ``sshd -T`` output into ``{key: [tokens...]}`` (lowercase keys, accumulated)."""
    raw = {}
    for line in text.splitlines():
        d = split_directive(line)
        if d is None:
            continue
        key, args = d
        key = ALIASES.get(key, key)
        raw.setdefault(key, []).extend(args)
    return raw


def normalise_config(raw):
    """Allowlist and normalise raw ``{key: [tokens]}``. Returns ``(config, problems)``."""
    cfg, problems, _trunc = normalise_config_ex(raw)
    return cfg, problems


def normalise_config_ex(raw):
    """As :func:`normalise_config` plus the sorted keys whose value was cut (a list past
    ``MAX_LIST_ITEMS`` items, an item over its length cap, ``authenticationmethods`` over 200
    characters): a cut value is a sorted prefix, never the full truth."""
    cfg = {}
    problems = []
    trunc = set()
    for key in sorted(raw):
        toks = raw[key]
        if key not in ALLOWLIST:
            continue
        if key in BOOL_KEYS:
            val = _YES.get(" ".join(toks).lower()) if len(toks) == 1 else None
            if val is None:
                problems.append("bad_value:" + key)
            else:
                cfg[key] = val
        elif key in ENUM_KEYS:
            val = " ".join(toks).lower() if len(toks) == 1 else ""
            if key == "permitrootlogin" and val == "without-password":
                val = "prohibit-password"
            if val not in ENUM_KEYS[key]:
                problems.append("bad_value:" + key)
            else:
                cfg[key] = val
        elif key in INT_KEYS:
            if len(toks) == 1 and re.match(r"^[0-9]{1,9}$", toks[0]):
                cfg[key] = int(toks[0])
            else:
                problems.append("bad_value:" + key)
        elif key in STR_KEYS:
            val = " ".join(toks).lower()
            if len(val) > 200:
                trunc.add(key)
            cfg[key] = clean_str(val, 200)
        elif key in LIST_INT_KEYS:
            ports = []
            for t in toks:
                if re.match(r"^[0-9]{1,5}$", t) and 0 < int(t) < 65536:
                    ports.append(int(t))
                else:
                    problems.append("bad_value:" + key)
            if ports:
                if len(set(ports)) > MAX_LIST_ITEMS:
                    trunc.add(key)
                cfg[key] = sorted(set(ports))[:MAX_LIST_ITEMS]
        elif key in LIST_STR_LOWER_KEYS:
            items = sorted(set(clean_str(t.lower(), 80) for t in toks))
            if len(items) > MAX_LIST_ITEMS or any(len(t) > 80 for t in toks):
                trunc.add(key)
            cfg[key] = items[:MAX_LIST_ITEMS]
        elif key in LIST_NAME_KEYS:
            items = sorted(set(clean_str(t, 80) for t in toks))
            if len(items) > MAX_LIST_ITEMS or any(len(t) > 80 for t in toks):
                trunc.add(key)
            cfg[key] = items[:MAX_LIST_ITEMS]
        elif key in LIST_TOKEN_KEYS:
            if len(toks) > MAX_LIST_ITEMS or any(len(t) > 120 for t in toks):
                trunc.add(key)
            cfg[key] = [clean_str(t, 120) for t in toks][:MAX_LIST_ITEMS]
        elif key == "authorizedkeyscommand":
            val = " ".join(toks).strip().lower()
            cfg[key] = "none" if val in ("none", "") else "set"
    return cfg, problems, sorted(trunc)


def config_delta(base_cfg, probe_cfg):
    """Keys whose value differs between a probe and the global config (absent -> None)."""
    delta = {}
    for key in sorted(set(base_cfg) | set(probe_cfg)):
        if base_cfg.get(key) != probe_cfg.get(key):
            delta[key] = probe_cfg.get(key)
    return delta


def parse_ssh_version(text):
    m = re.search(r"OpenSSH_([0-9]+\.[0-9]+(?:p[0-9]+)?)", text or "")
    return m.group(1) if m else None


# --------------------------------------------------------------- passwd users
def parse_passwd(passwd_text):
    """Rows of ``/etc/passwd`` as ``{name, uid, gid, login, ok}`` plus whether NIS ``+``/``-``
    marker lines are present (users the file does not list).

    ``login`` is "has a login shell"; ``ok`` is "the name can be passed as ``-C user=``".
    """
    rows = []
    nis = False
    for line in passwd_text.splitlines():
        if not line.strip() or line.startswith("#"):
            continue
        if line[0] in "+-":
            nis = True
            continue
        parts = line.split(":")
        if len(parts) < 7:
            continue
        name, uid_s, gid_s, shell = parts[0], parts[2], parts[3], parts[6].strip()
        if not uid_s.isdigit():
            continue
        rows.append({"name": name, "uid": int(uid_s), "gid": int(gid_s) if gid_s.isdigit() else None,
                     "login": shell not in NOLOGIN_SHELLS, "ok": bool(_USERNAME_RE.match(name))})
    return rows, nis


def login_users(passwd_text):
    """Names of accounts with a login shell, root excluded, sorted by uid then name."""
    rows, _nis = parse_passwd(passwd_text)
    return [r["name"] for r in sorted(rows, key=lambda r: (r["uid"], r["name"]))
            if r["name"] != "root" and r["login"] and r["ok"]]


def dropped_login_rows(passwd_text):
    """Login-shell accounts (root excluded) whose name cannot be probed: counted in ``users_total``."""
    rows, _nis = parse_passwd(passwd_text)
    return sum(1 for r in rows if r["name"] != "root" and r["login"] and not r["ok"])


def parse_group(text):
    """``({gid: name}, {user: {group, ...}}, nis_marker)`` from ``/etc/group``.

    A gid is named by its FIRST entry (``getgrgid``, which OpenSSH uses for every group of a user);
    an entry listing a user counts as that user's membership of its gid, i.e. under that first name.
    """
    by_gid = {}
    entries = []
    nis = False
    for line in text.splitlines():
        if not line.strip() or line.startswith("#"):
            continue
        if line[0] in "+-":
            nis = True
            continue
        parts = line.split(":")
        if len(parts) < 4:
            continue
        if parts[2].isdigit():
            gid = int(parts[2])
            by_gid.setdefault(gid, parts[0])
            entries.append((gid, parts[3]))
    members = {}
    for gid, users in entries:
        for u in users.split(","):
            if u.strip():
                members.setdefault(u.strip(), set()).add(by_gid[gid])
    return by_gid, members, nis


MAX_PATTERN_CHARS = 1024      # one pattern list (a Match User/Group value)
MAX_NAME_CHARS = 256
MAX_MATCH_STEPS = 200000      # work allowed for one pattern_list_match call


class PatternTooComplex(Exception):
    """A pattern list or name beyond the bounds of the linear matcher: the match is not attempted."""


def _wild(name, pat, budget):
    """``*`` / ``?`` wildcard match (whole string, case-sensitive, ``.`` and ``[`` are literal) by the
    iterative two-pointer algorithm: it remembers only the LAST ``*``, so it is O(len(name) *
    len(pat)) in the worst case and has no exponential backtracking. ``budget`` is a one-element
    list of remaining steps."""
    i = j = 0
    star = -1
    mark = 0
    n = len(name)
    m = len(pat)
    while i < n:
        budget[0] -= 1
        if budget[0] < 0:
            raise PatternTooComplex("match step budget exhausted")
        if j < m and pat[j] == "*":
            star = j
            mark = i
            j += 1
        elif j < m and (pat[j] == "?" or pat[j] == name[i]):
            i += 1
            j += 1
        elif star >= 0:
            j = star + 1
            mark += 1
            i = mark
        else:
            return False
    while j < m and pat[j] == "*":
        j += 1
    return j == m


def pattern_list_match(name, plist):
    """OpenSSH ``match_pattern_list``: 1 match, 0 none, -1 a negated pattern matched (it always wins).
    Case-sensitive, ``*`` and ``?`` only. Linear-time matching with a step bound; a list or name over
    the size bounds raises ``PatternTooComplex`` (the caller must treat the selection as unprobeable)."""
    if len(plist) > MAX_PATTERN_CHARS or len(name) > MAX_NAME_CHARS:
        raise PatternTooComplex("pattern list or name too long")
    budget = [MAX_MATCH_STEPS]
    got = 0
    for sub in plist.split(","):
        neg = sub.startswith("!")
        if neg:
            sub = sub[1:]
        if _wild(name, sub, budget):
            if neg:
                return -1
            got = 1
    return got


def _group_match(groups, plist):
    """OpenSSH ``ga_match_pattern_list`` over the user's group names."""
    found = False
    for g in sorted(groups):
        r = pattern_list_match(g, plist)
        if r < 0:
            return False
        if r == 1:
            found = True
    return found


def nss_users_unknown(ctx):
    """True when users or groups may come from somewhere ``/etc/passwd`` and ``/etc/group`` do not show
    (sssd, ldap, nis, winbind, extrausers, systemd userdb/homed, unreadable nsswitch.conf)."""
    st, text = ctx.read_text("/etc/nsswitch.conf", 1 << 18)
    if st == "missing":
        return False                      # glibc then uses files
    if st != "ok":
        return True
    for line in text.splitlines():
        line = line.split("#", 1)[0].strip()
        m = re.match(r"^(passwd|group)\s*:\s*(.*)$", line)
        if not m:
            continue
        srcs = re.sub(r"\[[^\]]*\]", " ", m.group(2)).split()
        if not set(s.lower() for s in srcs) <= NSS_FILES_SOURCES:
            return True
        if any(s.lower() == "systemd" for s in srcs):
            for d in USERDB_DIRS:
                lst, names = ctx.listdir(d)
                if lst == "ok" and names:
                    return True
                if lst not in ("ok", "missing"):
                    return True
    return False


def selection_extras(rows, group_text, matches, already, check=None):
    """Users to probe so that every behaviour a ``Match User/Group`` block can select is observed.

    A user's behaviour under ``sshd -T -C user=U`` depends only on which user/group criteria it
    satisfies, so one account per distinct satisfaction vector is enough: ``already`` (the users
    probed anyway) cover some vectors, the lowest-uid account of every other vector is added (any
    shell: a nologin SFTP account is the usual one). Returns ``(extra_names, reasons)``.
    """
    crits = sorted(set((k, p) for crit in matches for k, p in crit if k in ("user", "group")))
    reasons = set()
    if not crits:
        return [], reasons
    try:
        return _selection_extras(rows, group_text, crits, already, check, reasons)
    except PatternTooComplex:
        # a pattern list we will not evaluate: which users it selects is unknown
        return [], reasons | set(["user_pattern"])


def _selection_extras(rows, group_text, crits, already, check, reasons):
    if any(k == "user" and "@" in p for k, p in crits):
        reasons.add("user_pattern")
    by_gid, members, _nis = parse_group(group_text)
    by_name = {}
    for r in rows:
        by_name.setdefault(r["name"], r)

    def sig(name):
        r = by_name.get(name)
        groups = set(members.get(name, ()))
        if r is not None and r["gid"] in by_gid:
            groups.add(by_gid[r["gid"]])
        return tuple((pattern_list_match(name, p) == 1) if k == "user" else _group_match(groups, p)
                     for k, p in crits)

    covered = set(sig(n) for n in already)
    ticks = [0]

    def tick():
        ticks[0] += 1
        if check is not None and ticks[0] % 128 == 0:
            check()
    cands = sorted((r for r in rows if r["name"] != "root" and r["name"] not in already),
                   key=lambda r: (r["uid"], r["name"]))
    extras = []
    for r in cands:
        tick()
        if not r["ok"]:
            continue
        sg = sig(r["name"])
        if sg in covered:
            continue
        if len(extras) >= MAX_EXTRA_USERS:
            reasons.add("users_over_cap")
            break
        extras.append(r["name"])
        covered.add(sg)
    for r in cands:
        tick()
        if not r["ok"] and sig(r["name"]) not in covered:
            reasons.add("user_name_unprobeable")
            break
    return extras, reasons


# -------------------------------------------------------------- text config
def _glob(read_dir, pattern):
    """Expand a glob in the last path component only. Returns ``(paths, ok)``."""
    d, _, b = pattern.rpartition("/")
    if any(c in d for c in "*?["):
        return [], False
    if not any(c in b for c in "*?["):
        return [pattern], True
    status, names = read_dir(d or "/")
    if status == "missing":
        return [], True
    if status != "ok":
        return [], False
    return [d + "/" + n for n in names if fnmatch.fnmatchcase(n, b)], True


def parse_sshd_config(read_file, read_dir, main_path=MAIN_CONFIG):
    """Text-parse ``sshd_config`` and ``Include``s.

    ``read_file(path) -> (status, bytes)`` and ``read_dir(path) -> (status, names)`` are
    injected. Returns ``{raw, matches, files, problems, complete, include_dirs}``:
    ``raw`` are the *global* (pre-first-``Match``) settings with first-value-wins for
    scalar keys and accumulation for list keys; ``matches`` is a list of
    ``[(criterion, pattern), ...]``; ``complete`` is False when any file could not be
    read, so the caller must treat Match information as unknown.
    """
    state = {"raw": {}, "matches": [], "files": [], "problems": [], "complete": True,
             "in_match": False, "include_dirs": []}
    seen = set()

    def visit(path, depth):
        if depth > MAX_INCLUDE_DEPTH or len(state["files"]) >= MAX_FILES or path in seen:
            if path not in seen:
                state["complete"] = False
                state["problems"].append("include_limit")
            return
        seen.add(path)
        status, data = read_file(path)
        if status in ("missing",) and depth > 0:
            return
        if status not in ("ok",):
            state["complete"] = False
            state["files"].append({"path": path, "sha256": None, "size": 0})
            state["problems"].append("unreadable:" + path)
            return
        state["files"].append({"path": path, "sha256": hashlib.sha256(data).hexdigest(),
                               "size": len(data)})
        text = data.decode("utf-8", "replace")
        for line in text.splitlines():
            d = split_directive(line)
            if d is None:
                continue
            key, args = d
            if key == "include":
                for pat in args:
                    if not pat.startswith("/"):
                        pat = CONFIG_DIR + "/" + pat
                    idir = pat.rpartition("/")[0] or "/"
                    if not any(c in idir for c in "*?[") and idir not in state["include_dirs"]:
                        state["include_dirs"].append(idir)     # a deletion shows only on the directory
                    paths, ok_glob = _glob(read_dir, pat)
                    if not ok_glob:
                        state["complete"] = False
                        state["problems"].append("include_glob")
                    for p in paths:
                        visit(p, depth + 1)
                continue
            if key == "match":
                state["in_match"] = True
                crit = []
                if len(args) == 1 and args[0].lower() == "all":
                    crit.append(("all", ""))
                else:
                    i = 0
                    while i + 1 < len(args):
                        crit.append((args[i].lower(), args[i + 1]))
                        i += 2
                    if i < len(args):
                        crit.append((args[i].lower(), ""))
                state["matches"].append(crit)
                continue
            if state["in_match"]:
                continue
            key = ALIASES.get(key, key)
            slot = state["raw"]
            if key in MULTI_KEYS:
                slot.setdefault(key, []).extend(args)
            elif key not in slot:
                slot[key] = list(args)

    visit(main_path, 0)
    return state


def address_probe_points(patterns):
    """Representative client addresses for ``Match Address`` pattern lists.

    Returns ``(addrs, unprobed_reason_or_None)``. Behaviour as a function of the source
    address is constant on the atoms cut by every CIDR, so one address per atom suffices.
    """
    bounds = {4: set([0, 1 << 32]), 6: set([0, 1 << 128])}
    used = set()
    for pat in patterns:
        for item in pat.split(","):
            item = item.strip()
            if item.startswith("!"):
                item = item[1:]
            if item in ("", "*"):
                continue
            try:
                net = ipaddress.ip_network(item, strict=False)
            except ValueError:
                return [], "address_pattern"
            fam = net.version
            used.add(fam)
            start = int(net.network_address)
            bounds[fam].add(start)
            bounds[fam].add(start + net.num_addresses)
    addrs = []
    for fam in (4, 6):
        if fam not in used:
            continue
        pts = sorted(bounds[fam])
        for lo in pts[:-1]:
            rep = lo if lo else 1
            addrs.append(str(ipaddress.ip_address(rep) if fam == 4
                             else ipaddress.IPv6Address(rep)))
    if len(addrs) > MAX_ADDR_REPS:
        return [], "address_atoms"
    return addrs, None


def classify_match(matches, users_total):
    """Return ``(criteria_sorted, unprobed_reasons_sorted, address_patterns)``."""
    criteria = set()
    reasons = set()
    patterns = []
    for crit in matches:
        for key, pat in crit:
            criteria.add(key)
            if key == "address":
                patterns.append(pat)
            elif key in ("user", "group"):
                if users_total > MAX_LOGIN_USERS:
                    reasons.add("users_over_cap")
            elif key == "all":
                pass
            else:
                reasons.add("criterion_" + clean_str(key, 20))
    return sorted(criteria), sorted(reasons), patterns


def match_user_names_all(matches):
    """Every literal (non-wildcard, non-negated) user name that ``Match User`` blocks mention, sorted."""
    names = set()
    for crit in matches:
        for key, pat in crit:
            if key != "user":
                continue
            for item in pat.split(","):
                item = item.strip()
                if _USERNAME_RE.match(item):
                    names.add(item)
    return sorted(names)


def match_user_names(matches):
    """Literal user names of ``Match User`` blocks, capped at ``MAX_MATCH_USERS``.

    Such a user may have a non-login shell (or not exist in passwd) and so be absent from the
    login-user list; probing it by name closes that gap. Any case: ``Bob`` and ``bob`` differ.
    """
    return match_user_names_all(matches)[:MAX_MATCH_USERS]


def _users_for_probe(users, extra=()):
    names = ["root"] + users[:MAX_LOGIN_USERS]
    for n in extra:
        if n not in names:
            names.append(n)
    return names + [NONEXISTENT_USER]


def _label(user):
    return NONEXISTENT_LABEL if user == NONEXISTENT_USER else user


# ------------------------------------------------------------------ collector
def _numeric_pids(ctx):
    status, names = ctx.listdir("/proc")
    if status != "ok":
        return []
    return sorted(int(n) for n in names if n.isdigit())


def _root_process(ctx, pid):
    """True when ``/proc/<pid>/status`` shows real, effective, saved and fs uid all 0."""
    st, text = ctx.read_text("/proc/%d/status" % pid, 1 << 15)
    if st != "ok":
        return False
    for line in text.splitlines():
        if line.startswith("Uid:"):
            ids = line.split()[1:]
            return len(ids) >= 4 and all(i == "0" for i in ids[:4])
    return False


def _running_sshd_exe(ctx):
    """Path of the binary a root-owned ``sshd`` process is running (not deleted), else None.

    Only processes owned by root count: any user can rename its own process to ``sshd``.
    """
    for pid in _numeric_pids(ctx):
        st, comm = ctx.read_text("/proc/%d/comm" % pid, 64)
        if st != "ok" or comm.strip() != "sshd" or not _root_process(ctx, pid):
            continue
        st, target = ctx.readlink("/proc/%d/exe" % pid)
        if st != "ok" or target.endswith(" (deleted)") or not target.startswith("/"):
            continue
        if os.path.basename(target) != "sshd" or not ctx.isfile(target):
            continue
        if not os.access(ctx.fs_path(target), os.X_OK):
            continue
        # the path is read from the process's own mount namespace: outside the fixed system PATH it
        # names a file on THIS host that anyone may have planted, so it gets the /usr/local check
        if os.path.dirname(target) not in FIXED_DIRS and not _trusted_local_binary(ctx, target):
            continue
        return target
    return None


def _trusted_local_binary(ctx, path):
    """A binary outside the fixed PATH is run as root only if it and every directory above it up
    to /usr are owned by ``TRUSTED_UID`` and not group/world writable (Debian ships
    /usr/local/{bin,sbin} root:staff 2775: any staff member could plant it)."""
    try:
        sts = [os.stat(ctx.fs_path(path))]
        d = os.path.dirname(path)
        while d not in ("/", "/usr", ""):
            sts.append(os.stat(ctx.fs_path(d)))
            d = os.path.dirname(d)
    except OSError:
        return False
    if not stat.S_ISREG(sts[0].st_mode) or not sts[0].st_mode & 0o111:
        return False
    return all(x.st_uid == TRUSTED_UID and not x.st_mode & 0o022 for x in sts)


def find_sshd(ctx):
    """The sshd binary to run: the one a root sshd process is running, else the fixed system PATH,
    else /usr/local/{sbin,bin} only when root-owned and not group/world writable."""
    exe = _running_sshd_exe(ctx)
    if exe is not None:
        return exe
    exe = ctx.which("sshd")
    if exe is not None:
        return exe
    for d in LOCAL_SSHD_DIRS:
        cand = d + "/sshd"
        if ctx.isfile(cand) and _trusted_local_binary(ctx, cand):
            return cand
    return None


def sshd_evidence(ctx):
    """True when this host may run an SSH server although no usable sshd binary was found, i.e.
    "not installed" cannot be concluded. Deliberately broad: ssh-like process names (any case, comm or
    exe), a config or unit file, an untrusted binary in /usr/local, a listener on 22, or any
    non-loopback TCP listener that is not attributed to a program on the short NON_SSH_COMMS list
    (unattributed, a proxy such as docker-proxy, another SSH server such as gitea, ...). Absence of all of these says "no OpenSSH server we can
    see", never "no SSH server": the consumer must not derive more from it."""
    if ctx.exists(MAIN_CONFIG) or ctx.exists("/etc/dropbear"):
        return True
    for d in ("/etc/systemd/system", "/usr/lib/systemd/system", "/lib/systemd/system"):
        for n in ("ssh.service", "sshd.service", "ssh.socket", "sshd.socket", "dropbear.service"):
            if ctx.exists(d + "/" + n):
                return True
    for d in LOCAL_SSHD_DIRS:
        if ctx.exists(d + "/sshd"):
            return True
    for pid in _numeric_pids(ctx):
        st, comm = ctx.read_text("/proc/%d/comm" % pid, 64)
        names = [comm.strip().lower()] if st == "ok" else []
        lst, target = ctx.readlink("/proc/%d/exe" % pid)
        if lst == "ok":
            names.append(os.path.basename(target.replace(" (deleted)", "")).lower())
        if any(h in n for n in names for h in SSH_NAME_HINTS):
            return True
    from . import listeners as _lst
    sec = _lst.collect(ctx)
    if sec["s"] != "ok":
        # no /proc/net/tcp at all says nothing; any other failure leaves listeners unseen
        return not (sec["s"] == "unavailable" and sec["reason"] == "unsupported_platform")
    if sec["partial"]:
        return True
    for r in sec["v"]["listeners"]:
        if r["proto"] != "tcp":
            continue
        if r["port"] == 22:
            return True
        if r["bind_class"] == "loopback":
            continue
        if r["pid"] is None or (r["comm"] or "").lower() not in NON_SSH_COMMS:
            return True
    return False


def socket_activated(ctx):
    for d in ("/etc/systemd/system/sockets.target.wants", "/usr/lib/systemd/system/sockets.target.wants",
              "/lib/systemd/system/sockets.target.wants"):
        for n in ("ssh.socket", "sshd.socket"):
            if ctx.exists(d + "/" + n):
                return True
    return False


def _clk_tck():
    try:
        return int(os.sysconf("SC_CLK_TCK"))
    except (AttributeError, OSError, ValueError):
        return 100


SSHD_FLAG_OPTS = frozenset("46DdeGiqTtV")          # sshd(8) options without an argument
SSHD_ARG_OPTS = frozenset("BCcEfghkopRu")           # with an argument (the rest of the token or the next)
_CFG_PATH_RE = re.compile(r"^/[A-Za-z0-9_./+@-]{1,255}$")


def _proc_stat(ctx, pid):
    """``(ppid, starttime_ticks)`` from ``/proc/<pid>/stat`` (comm may contain spaces/parens)."""
    st, text = ctx.read_text("/proc/%d/stat" % pid, 4096)
    if st != "ok" or ")" not in text:
        return None, None
    rest = text[text.rindex(")") + 1:].split()
    try:
        return int(rest[1]), int(rest[19])
    except (IndexError, ValueError):
        return None, None


def _sshd_masters(ctx):
    """pids of root-owned ``sshd`` processes whose parent is not itself an sshd (the listeners)."""
    cands = {}
    for pid in _numeric_pids(ctx):
        st, comm = ctx.read_text("/proc/%d/comm" % pid, 64)
        if st == "ok" and comm.strip() == "sshd" and _root_process(ctx, pid):
            cands[pid] = _proc_stat(ctx, pid)
    return sorted(p for p, (ppid, _t) in cands.items() if ppid not in cands)


def _cmdline_facts(ctx, pid):
    """``(config_path_or_None, overrides_or_None, ok)``: the ``-f`` path (path only) and whether
    any option that changes the configuration (-o, -p, -4, -6) is present. Nothing else of the
    command line is kept."""
    st, data = ctx.read_bytes("/proc/%d/cmdline" % pid, 1 << 16)
    if st != "ok" or not data:
        return None, None, False
    toks = [t for t in re.split(r"[\0\s]+", data.decode("utf-8", "replace")) if t]
    path = None
    overrides = False
    bad_path = False
    skip = False
    for i, t in enumerate(toks):
        if skip:
            skip = False
            continue
        if len(t) < 2 or t[0] != "-" or t == "--":
            continue
        # getopt clusters: -Df /path, -Df/path, -Do Opt=v, -D4
        for j in range(1, len(t)):
            c = t[j]
            if c in SSHD_FLAG_OPTS:
                if c in "46":
                    overrides = True
                continue
            if c in SSHD_ARG_OPTS:
                arg = t[j + 1:]
                if not arg and i + 1 < len(toks):
                    arg = toks[i + 1]
                    skip = True
                if c == "f":
                    if _CFG_PATH_RE.match(arg):
                        path = arg
                    else:
                        bad_path = True
                elif c in "opghc":            # options that set a directive (LoginGraceTime, HostKey, ...)
                    overrides = True
                break
            overrides = True           # an option letter we do not know: do not guess
            break
    if bad_path:
        overrides = True
    return path, overrides, True


def _config_mtime_ns(ctx, files, include_dirs=()):
    """``(ns, doubt)``: newest change time (ns, max of mtime and ctime) of the config files read, of
    every directory an ``Include`` reads from (also when no file is left in it: a deleted drop-in shows
    only there) and, for an Include directory that is gone, of its parent. Also of every symbolic link
    met on the way to any of them (``ctx.link_change_ns``: ``stat`` follows a link and so cannot see it
    being repointed). ``doubt`` is True when a link path cannot be resolved with confidence."""
    best = None
    doubt = False
    dirs = set(include_dirs)

    def take(key):
        return key if best is None else max(best, key)

    paths = []
    for f in files:
        key = ctx.change_ns(f["path"])
        if key is not None:
            best = take(key)
        paths.append(f["path"])
        d = os.path.dirname(f["path"])
        if f["path"] != MAIN_CONFIG and d != CONFIG_DIR:
            dirs.add(d)
    for d in sorted(dirs):
        key = ctx.change_ns(d)
        if key is None:
            key = ctx.change_ns(os.path.dirname(d.rstrip("/")) or "/")
        if key is not None:
            best = take(key)
        paths.append(d)
    if MAIN_CONFIG not in paths:
        paths.append(MAIN_CONFIG)
    for p in paths:
        key, bad = ctx.link_change_ns(p)
        if key is not None:
            best = take(key)
        doubt = doubt or bad
    return best, doubt


def daemon_evidence(ctx, binary, files, activated, include_dirs=()):
    """Facts about the RUNNING sshd, to compare with what ``sshd -T`` says about the files.

    Returns ``(daemon, reasons)``. ``daemon`` always has the same keys (null = could not tell):
    ``found, masters, pid, start_epoch, reexec_epoch, config_path, config_default,
    options_override, binary_matches, config_mtime, reload_pending``. ``reload_pending`` is true
    when the config files (or a symbolic link on the way to one) changed after the daemon
    (re)started, or the daemon runs a different config file / extra options / another binary, so
    ``sshd -T`` of the default file need not be what runs; null when it could not be determined (no
    daemon seen, no start time, an unresolvable link); false only on positive evidence. Null always
    adds the ``daemon_unverified`` reason, so the section is approximate, never exact. A reload (SIGHUP
    re-exec) keeps the process start time, so the pid file mtime is used to see it. No argument
    content is ever kept.
    """
    d = {"found": False, "masters": 0, "pid": None, "start_epoch": None, "reexec_epoch": None,
         "config_path": None, "config_default": None, "options_override": None,
         "binary_matches": None, "config_mtime": None, "reload_pending": None}
    reasons = set()
    cfg_ns, link_doubt = _config_mtime_ns(ctx, files, include_dirs)
    if cfg_ns is not None:
        d["config_mtime"] = cfg_ns // 1000000000
    masters = _sshd_masters(ctx)
    d["masters"] = len(masters)
    if not masters:
        if activated:
            d["reload_pending"] = False      # socket activation: sshd reads the files per connection
        else:
            reasons.add("daemon_unverified")
        return d, reasons
    pid = masters[0]
    d["found"] = True
    d["pid"] = pid
    if len(masters) > 1:
        reasons.add("daemon_ambiguous")
    _ppid, ticks = _proc_stat(ctx, pid)
    start_ns = None
    st, stat_text = ctx.read_text("/proc/stat", 1 << 16)
    btime = None
    if st == "ok":
        for line in stat_text.splitlines():
            if line.startswith("btime "):
                try:
                    btime = int(line.split()[1])
                except (IndexError, ValueError):
                    btime = None
    if ticks is not None and btime is not None:
        d["start_epoch"] = btime + ticks // _clk_tck()
        start_ns = d["start_epoch"] * 1000000000
    path, overrides, have_cmd = _cmdline_facts(ctx, pid)
    differs = False
    if have_cmd:
        d["config_path"] = path
        d["config_default"] = path is None or path == MAIN_CONFIG
        d["options_override"] = bool(overrides)
        differs = (not d["config_default"]) or bool(overrides)
    lst, target = ctx.readlink("/proc/%d/exe" % pid)
    if lst == "ok":
        if target.endswith(" (deleted)"):
            d["binary_matches"] = False
        else:
            same = os.path.realpath(ctx.fs_path(target)) == os.path.realpath(ctx.fs_path(binary))
            d["binary_matches"] = bool(same)
        if d["binary_matches"] is False:
            reasons.add("daemon_binary_differs")
    reexec_ns = None
    for pf in PIDFILES:
        pst, ptext = ctx.read_text(pf, 64)
        if pst == "ok" and ptext.strip() == str(pid):
            key = ctx.stat_key(pf)
            if key is not None:
                reexec_ns = key[2]
                d["reexec_epoch"] = key[2] // 1000000000
            break
    if differs:
        reasons.add("daemon_config_differs")
        d["reload_pending"] = True
    elif link_doubt:
        pass                                  # a link we could not resolve: no positive evidence
    elif cfg_ns is not None and (start_ns is not None or reexec_ns is not None):
        eff = max(start_ns or 0, reexec_ns or 0)
        d["reload_pending"] = cfg_ns > eff
        if d["reload_pending"]:
            reasons.add("reload_pending")
    if d["reload_pending"] is None:
        reasons.add("daemon_unverified")      # null is never "current": the fact is approximate
    return d, reasons


def _read_text_config(ctx):
    def rf(p):
        return ctx.read_bytes(p, MAX_FILE_BYTES)

    def rd(p):
        return ctx.listdir(p)
    return parse_sshd_config(rf, rd)


def _text_result(ctx, tc, binary, version):
    cfg, _problems, trunc = normalise_config_ex(tc["raw"])
    crit, _reasons, _pats = classify_match(tc["matches"], 0)
    activated = socket_activated(ctx)
    daemon, _dreasons = daemon_evidence(ctx, binary, tc["files"], activated, tc.get("include_dirs", ()))
    v = {
        "installed": True, "source": "text", "version": version,
        "config": cfg,
        "probes": {"addrs": [], "users_probed": 0, "users_total": 0, "planned": 0, "done": 0,
                   "deltas": []},
        "match": {"blocks": len(tc["matches"]), "criteria": crit, "known": bool(tc["complete"]),
                  "unprobed": True, "unprobed_reasons": ["text_source"]},
        "files": tc["files"],
        "socket_activated": activated,
        "daemon": daemon,
        "binary": binary,
    }
    if trunc:
        v["truncated"] = trunc
    return base.ok(v, conf="approximate", partial=not tc["complete"])


def collect(ctx):
    if not ctx.platform.startswith("linux"):
        return base.unavailable("unsupported_platform")
    if ctx.containerised:
        return base.unavailable("containerised_agent")
    binary = find_sshd(ctx)
    if binary is None:
        if sshd_evidence(ctx):
            return base.unavailable("no_data")
        return base.unavailable("tool_missing")

    ver_text = ""
    for argv in (["ssh", "-V"], [binary, "-V"]):
        exe = argv[0] if argv[0] == binary else ctx.which(argv[0])
        if exe is None:
            continue
        r = ctx.run([exe] + argv[1:], timeout=5, max_bytes=65536)
        ver_text = (r.get("out") or "") + " " + (r.get("err_tail") or "")
        if parse_ssh_version(ver_text):
            break
    version = parse_ssh_version(ver_text)

    tc = _read_text_config(ctx)
    ctx.check()
    res = ctx.run([binary, "-T"], timeout=15, max_bytes=1 << 20)
    failure = base.classify_run(res, "sshd -T")
    if failure is not None or not res["out"].strip():
        if tc["files"] and tc["files"][0]["sha256"] is not None:
            return _text_result(ctx, tc, binary, version)
        if failure is not None:
            if failure["s"] == "unavailable" and failure["reason"] == "tool_missing":
                return base.unavailable("no_data")
            return failure
        return base.error("parse_error", "sshd -T produced no output")

    cfg, problems, trunc = normalise_config_ex(parse_sshd_T(res["out"]))
    if problems or not cfg:
        return base.error("parse_error", "sshd -T: " + ",".join(problems[:4] or ["no keys"]))
    trunc = set(trunc)

    st, passwd = ctx.read_text("/etc/passwd", 1 << 21)
    users_known = st == "ok"
    rows, nis = parse_passwd(passwd) if users_known else ([], False)
    users = login_users(passwd) if users_known else []
    users_total = len(users) + (dropped_login_rows(passwd) if users_known else 0)

    crit, reasons, patterns = classify_match(tc["matches"], users_total)
    reasons = set(reasons)
    if not tc["complete"]:
        reasons.add("config_unreadable")
    if not users_known:
        reasons.add("passwd_unreadable")
    addrs = list(PROBE_ADDRS)
    if patterns:
        reps, why = address_probe_points(patterns)
        if why:
            reasons.add(why)
        for a in reps:
            if a not in addrs:
                addrs.append(a)
    literals = match_user_names_all(tc["matches"])
    if len(literals) > MAX_MATCH_USERS:
        reasons.add("users_over_cap")
    literals = literals[:MAX_MATCH_USERS]
    extras = []
    if any(k in ("user", "group") for c in tc["matches"] for k, _p in c):
        # which users a Match block selects must be enumerable from the files, else it is unknown
        gst, gtext = ctx.read_text("/etc/group", 1 << 21)
        g_nis = False
        if gst == "ok":
            g_nis = parse_group(gtext)[2]
        elif gst == "missing":
            gtext = ""
        if nis or g_nis or nss_users_unknown(ctx) or gst not in ("ok", "missing"):
            reasons.add("nss_users_unknown")
        if users_known:
            probed = ["root"] + users[:MAX_LOGIN_USERS] + [n for n in literals] + [NONEXISTENT_USER]
            extras, why = selection_extras(rows, gtext if gst == "ok" else "", tc["matches"], probed,
                                          check=ctx.check)
            reasons |= why
    names = _users_for_probe(users, literals + [e for e in extras if e not in literals])
    plan = [(u, a) for u in names for a in addrs]
    if len(plan) > MAX_PROBE_RUNS:
        reasons.add("probe_cap")
        plan = plan[:MAX_PROBE_RUNS]
    done = 0
    deltas = []
    for user, addr in plan:
        if ctx.time_left() < 6:
            reasons.add("probe_budget")
            break
        r = ctx.run([binary, "-T", "-C", "user=%s,host=%s,addr=%s" % (user, PROBE_HOST, addr)],
                    timeout=PROBE_TIMEOUT_S, max_bytes=1 << 20)
        if base.classify_run(r, "sshd -T -C") is not None or not r["out"].strip():
            reasons.add("probe_failed")
            continue
        pcfg, pprob, ptrunc = normalise_config_ex(parse_sshd_T(r["out"]))
        if pprob or not pcfg:
            reasons.add("probe_failed")
            continue
        trunc.update(ptrunc)
        done += 1
        d = config_delta(cfg, pcfg)
        if d:
            deltas.append({"user": _label(user), "addr": addr, "delta": d})
    if done < len(plan):
        reasons.add("probe_incomplete")
    if deltas and not tc["matches"]:
        # probes disagree with a config we believed Match-free: our text view is wrong
        reasons.add("unexplained_delta")
    if trunc:
        reasons.add("config_truncated")
    activated = socket_activated(ctx)
    daemon, dreasons = daemon_evidence(ctx, binary, tc["files"], activated, tc.get("include_dirs", ()))
    reasons |= dreasons
    deltas.sort(key=lambda x: (x["user"], x["addr"]))
    unprobed = bool(reasons)
    v = {
        "installed": True, "source": "sshd_T", "version": version,
        "config": cfg,
        "probes": {"addrs": sorted(addrs), "users_probed": len(names) - 1,
                   "users_total": users_total, "planned": len(plan), "done": done,
                   "deltas": deltas},
        "match": {"blocks": len(tc["matches"]), "criteria": crit, "known": bool(tc["complete"]),
                  "unprobed": unprobed, "unprobed_reasons": sorted(reasons)},
        "files": tc["files"],
        "socket_activated": activated,
        "daemon": daemon,
        "binary": binary,
    }
    if trunc:
        v["truncated"] = sorted(trunc)
    conf = "approximate" if unprobed else "exact"
    return base.ok(v, conf=conf, partial=False)
