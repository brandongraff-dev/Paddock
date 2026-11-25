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
import re

from . import base
from .base import clean_str

MAIN_CONFIG = "/etc/ssh/sshd_config"
CONFIG_DIR = "/etc/ssh"
SSHD_CANDIDATES = ("/usr/sbin/sshd", "/sbin/sshd", "/usr/local/sbin/sshd", "/usr/bin/sshd")
PROBE_ADDRS = ("203.0.113.7", "10.255.255.1")
PROBE_HOST = "probe.invalid"
NONEXISTENT_USER = "paddock-nonexistent-probe"
NONEXISTENT_LABEL = "<nonexistent>"
MAX_LOGIN_USERS = 20
MAX_MATCH_USERS = 10
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
_USERNAME_RE = re.compile(r"^[a-z_][a-z0-9_.-]{0,31}$")

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
    cfg = {}
    problems = []
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
            cfg[key] = clean_str(" ".join(toks).lower(), 200)
        elif key in LIST_INT_KEYS:
            ports = []
            for t in toks:
                if re.match(r"^[0-9]{1,5}$", t) and 0 < int(t) < 65536:
                    ports.append(int(t))
                else:
                    problems.append("bad_value:" + key)
            if ports:
                cfg[key] = sorted(set(ports))[:MAX_LIST_ITEMS]
        elif key in LIST_STR_LOWER_KEYS:
            cfg[key] = sorted(set(clean_str(t.lower(), 80) for t in toks))[:MAX_LIST_ITEMS]
        elif key in LIST_NAME_KEYS:
            cfg[key] = sorted(set(clean_str(t, 80) for t in toks))[:MAX_LIST_ITEMS]
        elif key in LIST_TOKEN_KEYS:
            cfg[key] = [clean_str(t, 120) for t in toks][:MAX_LIST_ITEMS]
        elif key == "authorizedkeyscommand":
            val = " ".join(toks).strip().lower()
            cfg[key] = "none" if val in ("none", "") else "set"
    return cfg, problems


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
def login_users(passwd_text):
    """Names of accounts with a login shell, root excluded, sorted by uid then name."""
    rows = []
    for line in passwd_text.splitlines():
        parts = line.split(":")
        if len(parts) < 7 or line.startswith("#"):
            continue
        name, uid_s, shell = parts[0], parts[2], parts[6].strip()
        if name == "root" or not uid_s.isdigit():
            continue
        if shell in NOLOGIN_SHELLS:
            continue
        if not _USERNAME_RE.match(name):
            continue
        rows.append((int(uid_s), name))
    rows.sort()
    return [n for _, n in rows]


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
    injected. Returns ``{raw, matches, files, problems, complete}``:
    ``raw`` are the *global* (pre-first-``Match``) settings with first-value-wins for
    scalar keys and accumulation for list keys; ``matches`` is a list of
    ``[(criterion, pattern), ...]``; ``complete`` is False when any file could not be
    read, so the caller must treat Match information as unknown.
    """
    state = {"raw": {}, "matches": [], "files": [], "problems": [], "complete": True,
             "in_match": False}
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


def match_user_names(matches):
    """Literal (non-wildcard, non-negated) user names that ``Match User`` blocks mention.

    Such a user may have a non-login shell and so be absent from the login-user list; probing
    it by name closes that gap. Sorted, capped at ``MAX_MATCH_USERS``.
    """
    names = set()
    for crit in matches:
        for key, pat in crit:
            if key != "user":
                continue
            for item in pat.split(","):
                item = item.strip()
                if _USERNAME_RE.match(item):
                    names.add(item)
    return sorted(names)[:MAX_MATCH_USERS]


def _users_for_probe(users, extra=()):
    names = ["root"] + users[:MAX_LOGIN_USERS]
    for n in extra:
        if n not in names:
            names.append(n)
    return names + [NONEXISTENT_USER]


def _label(user):
    return NONEXISTENT_LABEL if user == NONEXISTENT_USER else user


# ------------------------------------------------------------------ collector
def find_sshd(ctx):
    return ctx.which("sshd", extra_dirs=["/usr/local/sbin", "/usr/local/bin"])


def sshd_evidence(ctx):
    """True when something on this host looks like an SSH server even though no binary was found."""
    if ctx.exists(MAIN_CONFIG):
        return True
    status, names = ctx.listdir("/proc")
    if status == "ok":
        for n in names:
            if n.isdigit():
                st, comm = ctx.read_text("/proc/%s/comm" % n, 64)
                if st == "ok" and comm.strip() in ("sshd", "dropbear", "sshd-session"):
                    return True
    from . import listeners as _lst
    for fname, fam in (("tcp", 4), ("tcp6", 6)):
        st, text = ctx.read_text("/proc/net/" + fname, 1 << 22)
        if st == "ok":
            rows, _bad = _lst.parse_proc_net(text, "tcp", fam)
            if any(r["port"] == 22 for r in rows):
                return True
    return False


def socket_activated(ctx):
    for d in ("/etc/systemd/system/sockets.target.wants", "/usr/lib/systemd/system/sockets.target.wants",
              "/lib/systemd/system/sockets.target.wants"):
        for n in ("ssh.socket", "sshd.socket"):
            if ctx.exists(d + "/" + n):
                return True
    return False


def _read_text_config(ctx):
    def rf(p):
        return ctx.read_bytes(p, MAX_FILE_BYTES)

    def rd(p):
        return ctx.listdir(p)
    return parse_sshd_config(rf, rd)


def _text_result(ctx, tc, binary, version):
    cfg, _problems = normalise_config(tc["raw"])
    crit, _reasons, _pats = classify_match(tc["matches"], 0)
    v = {
        "installed": True, "source": "text", "version": version,
        "config": cfg,
        "probes": {"addrs": [], "users_probed": 0, "users_total": 0, "planned": 0, "done": 0,
                   "deltas": []},
        "match": {"blocks": len(tc["matches"]), "criteria": crit, "known": bool(tc["complete"]),
                  "unprobed": True, "unprobed_reasons": ["text_source"]},
        "files": tc["files"],
        "socket_activated": socket_activated(ctx),
        "binary": binary,
    }
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

    cfg, problems = normalise_config(parse_sshd_T(res["out"]))
    if problems or not cfg:
        return base.error("parse_error", "sshd -T: " + ",".join(problems[:4] or ["no keys"]))

    st, passwd = ctx.read_text("/etc/passwd", 1 << 21)
    users = login_users(passwd) if st == "ok" else []
    users_total = len(users)
    users_known = st == "ok"

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
    names = _users_for_probe(users, match_user_names(tc["matches"]))
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
        pcfg, pprob = normalise_config(parse_sshd_T(r["out"]))
        if pprob or not pcfg:
            reasons.add("probe_failed")
            continue
        done += 1
        d = config_delta(cfg, pcfg)
        if d:
            deltas.append({"user": _label(user), "addr": addr, "delta": d})
    if done < len(plan):
        reasons.add("probe_incomplete")
    if deltas and not tc["matches"]:
        # probes disagree with a config we believed Match-free: our text view is wrong
        reasons.add("unexplained_delta")
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
        "socket_activated": socket_activated(ctx),
        "binary": binary,
    }
    conf = "approximate" if unprobed else "exact"
    return base.ok(v, conf=conf, partial=False)
