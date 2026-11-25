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
    st, text = ctx.read_text(path, 4096)
    if st != "ok":
        return []
    return [ln.strip() for ln in text.splitlines() if ln.strip()]


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


def collect(ctx):
    if not ctx.platform.startswith("linux"):
        return base.unavailable("unsupported_platform")
    if ctx.containerised:
        return base.unavailable("containerised_agent")
    if not ctx.is_root and not ctx.can_read_net_admin:
        return base.unavailable("permission_denied")
    nft = ctx.which("nft")
    save4_legacy = ctx.which("iptables-legacy-save")
    save6_legacy = ctx.which("ip6tables-legacy-save")
    save4 = ctx.which("iptables-save")
    save6 = ctx.which("ip6tables-save")
    if not (nft or save4_legacy or save4):
        return base.unavailable("tool_missing")

    dumps = []
    readable = {"ip4": False, "ip6": False}
    nft_ok = False
    nft_failure = None
    if nft:
        res = ctx.run([nft, "-j", "list", "ruleset"], timeout=NFT_TIMEOUT_S, max_bytes=MAX_OUT)
        nft_failure = base.classify_run(res, "nft")
        if nft_failure is None:
            try:
                obj = json.loads(res["out"])
                dumps.append(fwmodel.normalise_nft(obj))
            except (ValueError, KeyError, TypeError, AttributeError, fwmodel.FwModelError):
                return base.error("parse_error", "nft json not understood")
            nft_ok = True
            readable = {"ip4": True, "ip6": True}
    ctx.check()

    flavour = "unknown"
    if save4:
        v = ctx.run([ctx.which("iptables") or "iptables", "--version"], timeout=5, max_bytes=4096)
        flavour = parse_ipt_flavour(v.get("out", "") + " " + v.get("err_tail", ""))

    loaded4 = _tables(ctx, "/proc/net/ip_tables_names")
    loaded6 = _tables(ctx, "/proc/net/ip6_tables_names")
    legacy_used = False
    for fam, name, loaded, lsave, gsave, prefix in (
            (4, "ip4", loaded4, save4_legacy, save4, "legacy4"),
            (6, "ip6", loaded6, save6_legacy, save6, "legacy6")):
        need = bool(loaded) or not nft_ok
        if not need:
            continue
        cmd = lsave
        if cmd is None and gsave and (not nft_ok or flavour in ("legacy", "unknown")) and (
                fam == 4 or flavour != "nft"):
            cmd = gsave
        if cmd is None:
            if loaded:
                readable[name] = False
            continue
        r = ctx.run([cmd], timeout=SAVE_TIMEOUT_S, max_bytes=MAX_OUT)
        f = base.classify_run(r, "iptables-save")
        if f is not None:
            readable[name] = False
            if not nft_ok and fam == 4:
                return f
            continue
        try:
            dumps.append(fwmodel.parse_iptables_save(r["out"], fam, prefix))
        except fwmodel.FwModelError:
            return base.error("parse_error", "iptables-save not understood")
        legacy_used = True
        readable[name] = True

    if not nft_ok and not legacy_used:
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
    if nft_ok and legacy_used:
        backend = "mixed"
    elif nft_ok:
        backend = "nft"
    else:
        backend = "legacy"
    try:
        model = fwmodel.build_model(merged, backend, _frontends(ctx), v6, readable)
    except fwmodel.FwTooLarge:
        return base.error("truncated", "more than %d firewall rules" % fwmodel.MAX_RULES)
    except fwmodel.FwModelError as exc:
        return base.error("parse_error", clean_str("model: %s" % exc, 100))
    if model["rule_count"] == 0 and not merged["chains"] and nft_ok and not legacy_used:
        model["backend"] = "none"
    conf = "exact" if model["flat_view"]["confidence"] == "exact" else "approximate"
    return base.ok(model, conf=conf, partial=False)
