"""patch (lite) collector: OS identity, package manifest, pending security updates, kernel.

Facts only: no CVE matching, no verdicts (KEV matching is P2.1). The package manifest digest
is sent every time; the full list only when ``ctx.known_manifest_sha`` differs. Each part
is a sub-block with its own ``state`` (``ok|unavailable|error``) so one failing command does
not hide the others; the section is ``partial`` when any sub-block is not ok. Python 3.8
syntax only.
"""
import hashlib
import platform as _platform
import re

from . import base
from .base import clean_str, payload_bytes

MAX_PACKAGES = 8000
MAX_SEC_NAMES = 200
MAX_REBOOT_PKGS = 50
MAX_KERNELS = 20
_TIMER_DIRS = ("/etc/systemd/system/timers.target.wants",
               "/usr/lib/systemd/system/timers.target.wants",
               "/lib/systemd/system/timers.target.wants")


# ----------------------------------------------------------------- sub-blocks
def _sb_ok(**kw):
    d = {"state": "ok"}
    d.update(kw)
    return d


def _sb_unavailable(reason, **kw):
    if reason not in base.UNAVAILABLE_REASONS:
        raise ValueError(reason)
    d = {"state": "unavailable", "reason": reason}
    d.update(kw)
    return d


def _sb_error(reason, detail="", **kw):
    if reason not in base.ERROR_REASONS:
        raise ValueError(reason)
    d = {"state": "error", "reason": reason, "detail": clean_str(detail, base.DETAIL_MAX)}
    d.update(kw)
    return d


def _sb_from_failure(sec):
    if sec["s"] == "unavailable":
        return _sb_unavailable(sec["reason"])
    return _sb_error(sec["reason"], sec.get("detail", ""))


# --------------------------------------------------------------------- parsers
def parse_os_release(text):
    kv = {}
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        k, _, v = line.partition("=")
        v = v.strip()
        if len(v) >= 2 and v[0] == v[-1] and v[0] in "\"'":
            v = v[1:-1]
        kv[k.strip()] = v
    ident = kv.get("ID", "").lower()
    like = [t for t in kv.get("ID_LIKE", "").lower().split() if t]
    toks = set([ident] + like)
    if toks & set(["debian", "ubuntu"]):
        family = "debian"
    elif toks & set(["rhel", "fedora", "centos", "rocky", "almalinux", "amzn", "ol"]):
        family = "rhel"
    elif toks & set(["suse", "opensuse", "sles"]):
        family = "suse"
    elif ident == "alpine":
        family = "alpine"
    else:
        family = "other"
    codename = kv.get("VERSION_CODENAME") or kv.get("UBUNTU_CODENAME") or ""
    return {
        "id": clean_str(ident, 32) or None,
        "id_like": sorted(set(clean_str(t, 32) for t in like)),
        "version_id": clean_str(kv.get("VERSION_ID", ""), 32) or None,
        "codename": clean_str(codename.lower(), 32) or None,
        "pretty_name": clean_str(kv.get("PRETTY_NAME", ""), 80) or None,
        "family": family,
    }


def _strip_arch(name, arch):
    suffix = ":" + arch
    if name.endswith(suffix):
        return name[:-len(suffix)]
    return name


def parse_dpkg_query(text):
    """Rows ``[name, version, arch, source, source_version]`` for installed packages.

    Returns ``(rows, bad_lines, held)``. Only dpkg status letter ``i`` (installed) counts.
    """
    rows = []
    bad = 0
    held = 0
    for line in text.splitlines():
        if not line.strip():
            continue
        parts = line.split("\t")
        if len(parts) != 6:
            bad += 1
            continue
        name, ver, arch, _st, src, srcver = [p.strip() for p in parts]
        status = parts[3]
        if len(status) < 2 or status[1] != "i":
            continue
        if status[0] == "h":
            held += 1
        name = _strip_arch(name, arch)
        rows.append([name, ver, arch, src or name, srcver or ver])
    return rows, bad, held


def parse_dpkg_status(text):
    """Fallback parser for ``/var/lib/dpkg/status`` (no dpkg-query available)."""
    rows = []
    bad = 0
    held = 0
    for stanza in re.split(r"\n\s*\n", text):
        f = {}
        key = None
        for line in stanza.splitlines():
            if line[:1] in (" ", "\t"):
                continue
            if ":" not in line:
                bad += 1
                continue
            key, _, val = line.partition(":")
            f[key.strip()] = val.strip()
        if "Package" not in f:
            continue
        st = f.get("Status", "").split()
        if len(st) != 3 or st[2] != "installed":
            continue
        if st[0] == "hold":
            held += 1
        name, ver, arch = f["Package"], f.get("Version", ""), f.get("Architecture", "")
        src, srcver = name, ver
        if f.get("Source"):
            m = re.match(r"^(\S+)(?:\s+\(([^)]+)\))?", f["Source"])
            if m:
                src = m.group(1)
                srcver = m.group(2) or ver
        rows.append([name, ver, arch, src, srcver])
    return rows, bad, held


def parse_rpm_qf(text):
    """Rows from ``rpm -qa --qf '%{NAME}\\t%{EPOCHNUM}\\t%{VERSION}\\t%{RELEASE}\\t%{ARCH}\\t%{SOURCERPM}\\n'``."""
    rows = []
    bad = 0
    for line in text.splitlines():
        if not line.strip():
            continue
        parts = line.rstrip("\n").split("\t")
        if len(parts) != 6:
            bad += 1
            continue
        name, epoch, ver, rel, arch, srpm = [p.strip() for p in parts]
        if name == "gpg-pubkey":
            continue
        ep = "" if epoch in ("", "0", "(none)") else epoch + ":"
        evr = "%s%s-%s" % (ep, ver, rel)
        src, srcevr = name, evr
        s = re.sub(r"\.(no)?src\.rpm$", "", srpm)
        if s and s != "(none)":
            bits = s.rsplit("-", 2)
            if len(bits) == 3:
                src = bits[0]
                srcevr = "%s%s-%s" % (ep, bits[1], bits[2])
        rows.append([name, evr, arch, src, srcevr])
    return rows, bad


def manifest_digest(rows):
    ordered = sorted(rows)
    return hashlib.sha256(payload_bytes(ordered)).hexdigest(), ordered


_INST_RE = re.compile(
    r"^Inst\s+(\S+)\s+(?:\[([^\]]*)\]\s+)?\(([^\s]+)\s+(.*?)(?:\s+\[([^\]]*)\])?\)"
    r"(?:\s+\[[^\]]*\])*\s*$")
_SUMMARY_RE = re.compile(
    r"(\d+) upgraded, (\d+) newly installed, (\d+) to remove and (\d+) not upgraded")


def _origin_is_security(origin):
    """``Origin:Release/suite`` -> True when the suite is a ``*-security`` pocket."""
    suite = origin.strip().lower().rsplit("/", 1)[-1].strip()
    return suite.endswith("-security")


def parse_apt_sim(text):
    """Parse ``apt-get -s dist-upgrade``: counts and the names of security upgrades.

    Returns ``None`` when the summary line is missing (output not understood). ``unparsed``
    counts ``Inst`` lines that could not be read; a caller must not trust ``security`` then.
    """
    summary = None
    inst = 0
    unparsed = 0
    sec = set()
    removals = 0
    for line in text.splitlines():
        m = _SUMMARY_RE.search(line)
        if m:
            summary = m
            continue
        if line.startswith("Remv "):
            removals += 1
            continue
        if not line.startswith("Inst "):
            continue
        inst += 1
        im = _INST_RE.match(line.rstrip())
        if not im:
            unparsed += 1
            continue
        if any(_origin_is_security(o) for o in im.group(4).split(",")):
            sec.add(im.group(1))
    if summary is None:
        return None
    return {"total": inst, "security": len(sec), "unparsed": unparsed,
            "security_pkgs": sorted(sec)[:MAX_SEC_NAMES], "kept_back": int(summary.group(4)),
            "removals": max(removals, int(summary.group(3)))}


def parse_dnf_updateinfo(text):
    """Parse ``dnf -C -q updateinfo list --security`` into advisory/package counts."""
    advisories = set()
    pkgs = set()
    for line in text.splitlines():
        toks = line.split()
        if len(toks) < 3 or "Sec." not in toks[1] and "security" not in toks[1].lower():
            continue
        advisories.add(toks[0])
        nevra = toks[2]
        nevra = re.sub(r"\.[A-Za-z0-9_]+$", "", nevra)
        bits = nevra.rsplit("-", 2)
        pkgs.add(bits[0] if len(bits) == 3 else nevra)
    return {"total": len(advisories), "security": len(advisories),
            "security_pkgs": sorted(pkgs)[:MAX_SEC_NAMES], "kept_back": 0, "removals": 0}


def parse_yum_check_update(text):
    pkgs = set()
    for line in text.splitlines():
        if line.startswith("Obsoleting"):
            break
        toks = line.split()
        if len(toks) == 3 and "." in toks[0] and re.match(r"^[A-Za-z0-9_.+-]+$", toks[0]):
            pkgs.add(toks[0].rsplit(".", 1)[0])
    return {"total": len(pkgs), "security": len(pkgs),
            "security_pkgs": sorted(pkgs)[:MAX_SEC_NAMES], "kept_back": 0, "removals": 0}


def parse_apt_periodic(text):
    """``apt-config dump APT::Periodic`` -> unattended-upgrade interval in days (or None)."""
    m = re.search(r'APT::Periodic::Unattended-Upgrade\s+"(\d{1,4})"', text)
    return int(m.group(1)) if m else None


def parse_auto_conf(text, key="apply_updates"):
    m = re.search(r"^\s*%s\s*=\s*(\S+)" % re.escape(key), text, re.M)
    if not m:
        return None
    return m.group(1).strip().lower() in ("yes", "true", "1")


def kernel_packages(rows, family_mgr):
    """``[(release, package, evr)]`` for installed kernel packages."""
    out = []
    for name, evr, arch, _s, _sv in rows:
        if family_mgr == "dpkg":
            m = re.match(r"^linux-image-(?:unsigned-)?(\d.*)$", name)
            if m:
                out.append((m.group(1), name, evr))
        else:
            if name in ("kernel-core", "kernel"):
                out.append(("%s.%s" % (evr.split(":", 1)[-1], arch), name, evr))
    return sorted(out)


# ------------------------------------------------------------------- collection
def _collect_os(ctx):
    st, text = ctx.read_text("/etc/os-release", 1 << 16)
    if st == "missing":
        st, text = ctx.read_text("/usr/lib/os-release", 1 << 16)
    if st != "ok":
        return None, _sb_unavailable("no_data" if st == "missing" else "permission_denied")
    d = parse_os_release(text)
    d["arch"] = clean_str(ctx.cache.get("machine") or _platform.machine(), 16) or None
    return d, _sb_ok(**d)


def _collect_manifest(ctx):
    """Return ``(sub-block, rows or None, mgr or None)``."""
    mgr = None
    rows = []
    held = 0
    dq = ctx.which("dpkg-query")
    rpm = ctx.which("rpm")
    if dq:
        mgr = "dpkg"
        r = ctx.run([dq, "-W", "-f",
                     "${binary:Package}\t${Version}\t${Architecture}\t${db:Status-Abbrev}\t"
                     "${source:Package}\t${source:Version}\n"], timeout=60, max_bytes=8 << 20)
        f = base.classify_run(r, "dpkg-query")
        if f is not None:
            return _sb_from_failure(f), None, mgr
        rows, bad, held = parse_dpkg_query(r["out"])
    elif rpm:
        mgr = "rpm"
        r = ctx.run([rpm, "-qa", "--qf",
                     "%{NAME}\t%{EPOCHNUM}\t%{VERSION}\t%{RELEASE}\t%{ARCH}\t%{SOURCERPM}\n"],
                    timeout=60, max_bytes=8 << 20)
        f = base.classify_run(r, "rpm")
        if f is not None:
            return _sb_from_failure(f), None, mgr
        rows, bad = parse_rpm_qf(r["out"])
    elif ctx.exists("/var/lib/dpkg/status"):
        mgr = "dpkg"
        st, text = ctx.read_text("/var/lib/dpkg/status", 32 << 20)
        if st == "truncated":
            return _sb_error("truncated", "dpkg status too large"), None, mgr
        if st != "ok":
            return _sb_unavailable("permission_denied" if st == "denied" else "no_data"), None, mgr
        rows, bad, held = parse_dpkg_status(text)
    elif ctx.exists("/lib/apk/db/installed"):
        return _sb_unavailable("unsupported_platform"), None, None
    else:
        return _sb_unavailable("tool_missing"), None, None
    if bad:
        return _sb_error("parse_error", "%d unparseable package lines" % bad), None, mgr
    if not rows:
        return _sb_error("parse_error", "package manager returned no packages"), None, mgr
    if len(rows) > MAX_PACKAGES:
        return _sb_error("truncated", "more than %d packages" % MAX_PACKAGES), None, mgr
    digest, ordered = manifest_digest(rows)
    full = bool(ctx.force_full_manifest) or ctx.known_manifest_sha != digest
    sb = _sb_ok(mgr=mgr, count=len(ordered), sha256=digest, full=full, held=held)
    if full:
        sb["packages"] = ordered
    return sb, ordered, mgr


def _apt_age(ctx):
    for path in ("/var/lib/apt/periodic/update-success-stamp", "/var/lib/apt/lists"):
        m = ctx.mtime_s(path)
        if m is not None:
            return max(0, ctx.now_s() - m)
    return None


def _collect_pending(ctx, mgr):
    if mgr == "dpkg":
        apt = ctx.which("apt-get")
        if apt is None:
            return _sb_unavailable("tool_missing")
        r = ctx.run([apt, "-s", "-o", "Debug::NoLocking=1", "dist-upgrade"], timeout=90,
                    max_bytes=4 << 20)
        f = base.classify_run(r, "apt-get")
        if f is not None:
            return _sb_from_failure(f)
        parsed = parse_apt_sim(r["out"])
        if parsed is None:
            return _sb_error("parse_error", "apt-get -s summary not found")
        if parsed["unparsed"]:
            return _sb_error("parse_error", "%d apt Inst lines not understood" % parsed["unparsed"])
        del parsed["unparsed"]
        return _sb_ok(mgr="apt", metadata_age_s=_apt_age(ctx), **parsed)
    if mgr == "rpm":
        dnf = ctx.which("dnf")
        if dnf:
            r = ctx.run([dnf, "-C", "-q", "updateinfo", "list", "--security"], timeout=90,
                        max_bytes=4 << 20)
            f = base.classify_run(r, "dnf")
            if f is not None:
                if f["s"] == "error" and f["reason"] == "exit_nonzero" and "cache" in f["detail"].lower():
                    return _sb_unavailable("no_data")
                return _sb_from_failure(f)
            return _sb_ok(mgr="dnf", metadata_age_s=None, **parse_dnf_updateinfo(r["out"]))
        yum = ctx.which("yum")
        if yum:
            r = ctx.run([yum, "-C", "--security", "check-update"], timeout=90, max_bytes=4 << 20)
            if r.get("rc") in (0, 100) and not (r["missing"] or r["timed_out"] or r["truncated"]):
                return _sb_ok(mgr="yum", metadata_age_s=None, **parse_yum_check_update(r["out"]))
            f = base.classify_run(r, "yum")
            return _sb_from_failure(f) if f is not None else _sb_error("exit_nonzero", "yum")
        return _sb_unavailable("tool_missing")
    return _sb_unavailable("no_data")


def _timer_enabled(ctx, name):
    for d in _TIMER_DIRS:
        status, names = ctx.listdir(d)
        if status == "ok" and name in names:
            return True
        if status == "ok" and "*" in name:
            pre = name.split("*")[0]
            if any(n.startswith(pre) and n.endswith(".timer") for n in names):
                return True
    return False


def _collect_auto_update(ctx, mgr, names):
    if mgr == "dpkg":
        installed = "unattended-upgrades" in names
        days = None
        ac = ctx.which("apt-config")
        if ac:
            r = ctx.run([ac, "dump", "APT::Periodic"], timeout=10, max_bytes=1 << 16)
            if base.classify_run(r, "apt-config") is None:
                days = parse_apt_periodic(r["out"])
        return _sb_ok(mgr="unattended-upgrades", installed=installed,
                      interval_days=days,
                      timer_enabled=_timer_enabled(ctx, "apt-daily-upgrade.timer"))
    if mgr == "rpm":
        if "dnf-automatic" in names:
            st, text = ctx.read_text("/etc/dnf/automatic.conf", 1 << 17)
            return _sb_ok(mgr="dnf-automatic", installed=True,
                          apply=parse_auto_conf(text) if st == "ok" else None,
                          timer_enabled=_timer_enabled(ctx, "dnf-automatic*.timer"))
        if "yum-cron" in names:
            st, text = ctx.read_text("/etc/yum/yum-cron.conf", 1 << 17)
            return _sb_ok(mgr="yum-cron", installed=True,
                          apply=parse_auto_conf(text) if st == "ok" else None,
                          timer_enabled=None)
        return _sb_ok(mgr="none", installed=False, apply=None, timer_enabled=False)
    return _sb_unavailable("no_data")


def _livepatch(ctx):
    if ctx.exists("/snap/canonical-livepatch") or ctx.exists("/var/snap/canonical-livepatch"):
        return True
    st, names = ctx.listdir("/sys/kernel/livepatch")
    return st == "ok" and bool(names)


def _collect_kernel(ctx, rows, mgr):
    st, text = ctx.read_text("/proc/sys/kernel/osrelease", 128)
    if st != "ok" or not text.strip():
        return _sb_unavailable("no_data")
    running = clean_str(text.strip(), 80)
    live = _livepatch(ctx)
    if rows is None or mgr is None:
        return _sb_unavailable("no_data", running=running, livepatch=live)
    kernels = kernel_packages(rows, mgr)
    owner = None
    for rel, pkg, evr in kernels:
        if rel == running:
            owner = (pkg, evr)
            break
    if owner is None:
        return _sb_unavailable("unmanaged_kernel", running=running, livepatch=live)
    return _sb_ok(running=running, package=owner[0], package_version=owner[1],
                  installed=[k[0] for k in kernels][:MAX_KERNELS], livepatch=live)


def _collect_reboot(ctx, mgr):
    for path in ("/var/run/reboot-required", "/run/reboot-required"):
        if ctx.exists(path):
            pkgs = []
            st, text = ctx.read_text(path + ".pkgs", 1 << 16)
            if st == "ok":
                pkgs = sorted(set(clean_str(x.strip(), 80) for x in text.splitlines()
                                  if x.strip()))[:MAX_REBOOT_PKGS]
            return _sb_ok(required=True, pkgs=pkgs, source="file")
    if mgr == "dpkg":
        return _sb_ok(required=False, pkgs=[], source="file")
    if mgr == "rpm":
        nr = ctx.which("needs-restarting")
        cmd = [nr, "-r"] if nr else None
        if cmd is None:
            dnf = ctx.which("dnf")
            cmd = [dnf, "-C", "needs-restarting", "-r"] if dnf else None
        if cmd is None:
            return _sb_unavailable("tool_missing")
        r = ctx.run(cmd, timeout=60, max_bytes=1 << 20)
        if r["missing"] or r["timed_out"] or r["truncated"]:
            return _sb_from_failure(base.classify_run(r, "needs-restarting"))
        if r["rc"] == 1:
            return _sb_ok(required=True, pkgs=[], source="needs-restarting")
        if r["rc"] == 0:
            return _sb_ok(required=False, pkgs=[], source="needs-restarting")
        return _sb_error("exit_nonzero", "needs-restarting rc=%s" % r["rc"])
    return _sb_unavailable("no_data")


def collect(ctx):
    if not ctx.platform.startswith("linux"):
        return base.unavailable("unsupported_platform")
    if ctx.containerised:
        return base.unavailable("containerised_agent")
    _os_d, os_sb = _collect_os(ctx)
    ctx.check()
    manifest, rows, mgr = _collect_manifest(ctx)
    ctx.check()
    names = set(r[0] for r in rows) if rows else set()
    pending = _collect_pending(ctx, mgr)
    ctx.check()
    auto = _collect_auto_update(ctx, mgr, names) if rows is not None else _sb_unavailable("no_data")
    kernel = _collect_kernel(ctx, rows, mgr)
    reboot = _collect_reboot(ctx, mgr)
    blocks = {"os": os_sb, "manifest": manifest, "pending": pending, "auto_update": auto,
              "kernel": kernel, "reboot": reboot}
    states = [b["state"] for b in blocks.values()]
    if blocks["manifest"]["state"] != "ok" and blocks["os"]["state"] != "ok":
        # neither the identity nor the package list could be read: this is a failure, not data
        for key in ("manifest", "os"):
            b = blocks[key]
            if b["state"] == "error":
                return base.error(b["reason"], b.get("detail", ""))
        return base.unavailable(blocks["manifest"].get("reason", "no_data"))
    partial = any(s != "ok" for s in states)
    return base.ok(blocks, conf="exact", partial=partial)
