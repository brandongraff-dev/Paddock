"""firewall collector: the host's inbound packet filter as a canonical model.

Source of truth is ``nft -j list ruleset`` (this also covers iptables-nft) plus the legacy
``iptables-legacy-save`` / ``ip6tables-legacy-save`` when the kernel has legacy tables loaded.
``ufw`` and ``firewalld`` are recorded as ``frontends`` only, never as truth. All parsing and
modelling is in :mod:`fwmodel`; this module runs the tools and classifies failures.
Python 3.8 syntax only.
"""
import json
import re

from . import base, fwmodel
from .base import clean_str

NFT_TIMEOUT_S = 25
SAVE_TIMEOUT_S = 25
MAX_OUT = 4 * 1024 * 1024
PARSE_ERRORS = (ValueError, KeyError, TypeError, AttributeError, IndexError, fwmodel.FwModelError)


def parse_ufw_status(text):
    """``ufw status verbose`` -> frontend record."""
    state = "unknown"
    default_in = "unknown"
    rules = 0
    after_sep = False
    for line in text.splitlines():
        s = line.strip()
        m = re.match(r"^Status:\s*(\w+)", s)
        if m:
            state = "active" if m.group(1).lower() == "active" else (
                "inactive" if m.group(1).lower() == "inactive" else "unknown")
        m = re.match(r"^Default:\s*(\w+)\s*\(incoming\)", s)
        if m and m.group(1).lower() in ("deny", "allow", "reject"):
            default_in = m.group(1).lower()
        if s.startswith("--"):
            after_sep = True
            continue
        if after_sep and s:
            rules += 1
    return {"name": "ufw", "state": state, "default_incoming": default_in,
            "rules": min(rules, 1000)}


def parse_firewalld_state(rc, out):
    text = (out or "").strip().lower()
    if rc == 0 and text == "running":
        state = "running"
    elif text == "not running":
        state = "not_running"
    else:
        state = "unknown"
    return {"name": "firewalld", "state": state, "default_zone": None}


def parse_ipt_flavour(text):
    low = (text or "").lower()
    if "nf_tables" in low:
        return "nft"
    if "legacy" in low:
        return "legacy"
    if re.search(r"v\d+\.\d+", low):
        return "legacy"
    return "unknown"


def ipv6_enabled(ctx):
    """True when IPv6 can reach this host (a non-loopback v6 address and not disabled)."""
    st, text = ctx.read_text("/proc/sys/net/ipv6/conf/all/disable_ipv6", 16)
    if st == "ok" and text.strip() == "1":
        return False
    st, text = ctx.read_text("/proc/net/if_inet6", 1 << 20)
    if st != "ok":
        return False
    for line in text.splitlines():
        parts = line.split()
        if len(parts) >= 6 and parts[5] != "lo":
            return True
    return False


def _tables(ctx, path):
    """Names listed in ``/proc/net/ip{,6}_tables_names``.

    ``[]`` means the legacy table module is not loaded (file missing: nothing to read);
    ``None`` means the file exists but could not be read (the legacy state is unknown).
    """
    st, text = ctx.read_text(path, 4096)
    if st == "missing":
        return []
    if st != "ok":
        return None
    return [ln.strip() for ln in text.splitlines() if ln.strip()]


def _nf_tables_module(ctx):
    """True/False when ``/proc/modules`` says nf_tables is loaded; None when it cannot tell."""
    st, text = ctx.read_text("/proc/modules", 1 << 20)
    if st != "ok":
        return None
    for line in text.splitlines():
        if line.split(" ", 1)[0] == "nf_tables":
            return True
    return False


def _frontends(ctx):
    out = []
    ufw = ctx.which("ufw")
    if ufw is not None:
        r = ctx.run([ufw, "status", "verbose"], timeout=10, max_bytes=1 << 18)
        if base.classify_run(r, "ufw") is None:
            out.append(parse_ufw_status(r["out"]))
        else:
            out.append({"name": "ufw", "state": "unknown", "default_incoming": "unknown",
                        "rules": 0})
    fwd = ctx.which("firewall-cmd")
    if fwd is not None:
        r = ctx.run([fwd, "--state"], timeout=10, max_bytes=4096)
        rec = parse_firewalld_state(r.get("rc"), r.get("out"))
        if rec["state"] == "running":
            z = ctx.run([fwd, "--get-default-zone"], timeout=10, max_bytes=4096)
            if base.classify_run(z, "firewall-cmd") is None and re.match(
                    r"^[A-Za-z0-9_-]{1,32}$", z["out"].strip()):
                rec["default_zone"] = z["out"].strip()
        out.append(rec)
    return sorted(out, key=lambda x: x["name"])


def _flavour(ctx, binary_name):
    exe = ctx.which(binary_name)
    if exe is None:
        return "unknown"
    v = ctx.run([exe, "--version"], timeout=5, max_bytes=4096)
    return parse_ipt_flavour(v.get("out", "") + " " + v.get("err_tail", ""))


def collect(ctx):
    if not ctx.platform.startswith("linux"):
        return base.unavailable("unsupported_platform")
    if ctx.containerised:
        return base.unavailable("containerised_agent")
    if not ctx.is_root and not ctx.can_read_net_admin:
        return base.unavailable("permission_denied")
    nft = ctx.which("nft")
    tools = {4: {"legacy": ctx.which("iptables-legacy-save"), "generic": ctx.which("iptables-save"),
                 "name": "iptables"},
             6: {"legacy": ctx.which("ip6tables-legacy-save"), "generic": ctx.which("ip6tables-save"),
                 "name": "ip6tables"}}
    if not (nft or tools[4]["legacy"] or tools[4]["generic"]):
        return base.unavailable("tool_missing")

    # nft_state: ok (ruleset read) | failed (tool present, could not read) | missing
    dumps = []
    readable = {"ip4": False, "ip6": False}
    nft_state = "missing"
    nft_failure = None
    if nft:
        res = ctx.run([nft, "-j", "list", "ruleset"], timeout=NFT_TIMEOUT_S, max_bytes=MAX_OUT)
        nft_failure = base.classify_run(res, "nft")
        if nft_failure is None:
            try:
                obj = json.loads(res["out"])
                dumps.append(fwmodel.normalise_nft(obj))
            except PARSE_ERRORS:
                return base.error("parse_error", "nft json not understood")
            nft_state = "ok"
            readable = {"ip4": True, "ip6": True}
        else:
            nft_state = "failed"
    else:
        # no nft binary: a native nftables ruleset cannot be ruled out while nf_tables is loaded
        if _nf_tables_module(ctx) is False:
            readable = {"ip4": True, "ip6": True}
    ctx.check()

    loaded = {4: _tables(ctx, "/proc/net/ip_tables_names"),
              6: _tables(ctx, "/proc/net/ip6_tables_names")}
    legacy_used = False
    for fam, name in ((4, "ip4"), (6, "ip6")):
        t = tools[fam]
        names = loaded[fam]
        if names is None:  # the legacy table list exists but cannot be read
            readable[name] = False
            continue
        if not names:  # the legacy modules are not loaded: nothing to read
            continue
        # legacy tables are loaded: only a legacy-flavoured save tool can read them (the
        # nf_tables flavour of iptables-save shows a different set of tables)
        cmd = t["legacy"]
        if cmd is None and t["generic"] and _flavour(ctx, t["name"]) == "legacy":
            cmd = t["generic"]
        if cmd is None:
            readable[name] = False
            continue
        r = ctx.run([cmd], timeout=SAVE_TIMEOUT_S, max_bytes=MAX_OUT)
        f = base.classify_run(r, "iptables-save")
        if f is not None:
            readable[name] = False
            if nft_state != "ok" and fam == 4 and not dumps:
                return f
            continue
        try:
            dumps.append(fwmodel.parse_iptables_save(r["out"], fam, "legacy%d" % fam))
        except PARSE_ERRORS:
            return base.error("parse_error", "iptables-save not understood")
        legacy_used = True

    if not dumps:
        if nft_failure is not None:
            return nft_failure
        return base.unavailable("tool_missing")

    v6 = ipv6_enabled(ctx)
    try:
        merged = fwmodel.merge_dumps(dumps)
    except fwmodel.FwModelError:
        return base.error("parse_error", "duplicate chains")
    if ctx.exists("/proc/net/ip_vs"):
        merged["nat_rewrite"] = True
        merged["features"].add("ipvs")
    for d in ("/run/cilium", "/var/run/cilium"):
        if ctx.exists(d):
            merged["dataplane"].add("cilium")
    if nft_state == "ok" and legacy_used:
        backend = "mixed"
    elif nft_state == "ok":
        backend = "nft"
    else:
        backend = "legacy"
    try:
        model = fwmodel.build_model(merged, backend, _frontends(ctx), v6, readable)
    except fwmodel.FwTooLarge:
        return base.error("truncated", "more than %d firewall rules" % fwmodel.MAX_RULES)
    except PARSE_ERRORS as exc:
        return base.error("parse_error", clean_str("model: %s" % type(exc).__name__, 100))
    if model["rule_count"] == 0 and not merged["chains"] and nft_state == "ok" and not legacy_used:
        model["backend"] = "none"
    enabled = ["ip4"] + (["ip6"] if v6 else [])
    unread = [n for n in enabled if not readable[n]]
    conf = "exact" if model["flat_view"]["confidence"] == "exact" else "approximate"
    return base.ok(model, conf=conf, partial=bool(unread))
