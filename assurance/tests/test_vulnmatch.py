"""``paddock_assurance.vulnmatch``: the pure matcher behind ``std:kev-patched-within-Nd`` (contract 1.6 to 1.8).

Layout: loaders for the real-format fixtures, scope resolution, the evidence/freshness gates, per
``(cve, package)`` statuses, dates and the clock, the kernel rule, undecidable packages, the leaf
(``evaluate_leaf``), the fact ``data`` shape and its caps, determinism and hostile inputs
(contract 8.4 rows 2, 3, 4, 5 and 8). The adversarial rows are named after the mutation they pin
(contract 8.3, section A).
"""
from __future__ import annotations

import copy
import datetime as dt
import hashlib
import json
import pathlib
import random
import re
import subprocess
import sys
import time
from types import MappingProxyType

import pytest

from paddock_assurance.vulnmatch import (
    Evidence, Fix, FixIndex, HostInput, HostMeta, KernelInfo, KevEntry, KevSnapshot, OsInfo, ScopeInfo,
    SnapshotRef, check_identity, evaluate_leaf, kev_ids_sha, match_host, parse_rows, resolve_scope,
)
from paddock_assurance.vulnmatch import leaf as LEAF
from paddock_assurance.vulnmatch import scopes as SC

FIX = pathlib.Path(__file__).parent / "fixtures" / "vulnmatch"
UTC = dt.timezone.utc
NOW = dt.datetime(2026, 11, 26, 20, 0, tzinfo=UTC)
FIRST = dt.datetime(2026, 11, 20, 6, 0, tzinfo=UTC)            # our first sighting of the fixture rows
SHA = "ab" * 32


def D(y, m, d, h=0, mi=0, s=0):
    return dt.datetime(y, m, d, h, mi, s, tzinfo=UTC)


def Z(t):
    return t.strftime("%Y-%m-%dT%H:%M:%SZ")


def hours(n):
    return dt.timedelta(hours=n)


def days(n):
    return dt.timedelta(days=n)


# ------------------------------------------------------------------------------ the scopes table
def _scope(scope, family, vendor, release, dating=(), status="supported", until=None, keys=()):
    return ScopeInfo(scope=scope, family=family, vendor=vendor, release=release, status=status,
                     support_until=until, dating_sources=tuple(dating), max_staleness_s=172800,
                     key_ids=tuple(keys))


SCOPES = {s.scope: s for s in (
    _scope("debian:bookworm", "deb", "debian", "bookworm", ("dsa", "dla")),
    _scope("debian:trixie", "deb", "debian", "trixie", ("dsa", "dla")),
    _scope("ubuntu:jammy", "deb", "ubuntu", "jammy", ("usn",)),
    _scope("ubuntu:noble", "deb", "ubuntu", "noble", ("usn",)),
    _scope("rhel:8", "rpm", "rhel", "8"), _scope("rhel:9", "rpm", "rhel", "9"),
    _scope("alma:8", "rpm", "alma", "8"), _scope("alma:9", "rpm", "alma", "9"),
)}
PRIMARY = {"debian": "debian-tracker", "ubuntu": "ubuntu-oval", "rhel": "rhel-oval", "alma": "alma-errata"}

DEB12 = OsInfo(id="debian", version_id="12", codename="bookworm")
UBU24 = OsInfo(id="ubuntu", version_id="24.04", codename="noble")
ALMA9 = OsInfo(id="almalinux", version_id="9.5", codename=None)
RHEL9 = OsInfo(id="rhel", version_id="9.4", codename=None)


# ------------------------------------------------------------------------------ builders
def fixrow(cve, pkg, evr="", *, state="fixed", at=None, adv="", first=FIRST, scope="debian:bookworm",
           kind=None, modular=False, stream=""):
    if kind is None:
        kind = "binary" if scope.split(":")[0] in ("rhel", "alma") else "source"
    return Fix(scope=scope, cve=cve, pkg=pkg, pkg_kind=kind, state=state, fixed_evr=evr, advisory_id=adv,
               fixed_at=at, first_seen_at=first, modular=modular, stream=stream)


def kevrow(cve, added, *, first=D(2026, 11, 1), due=None, ransom=False):
    return KevEntry(cve=cve, date_added=added, first_seen_at=first, due_date=due, ransomware=ransom)


def kevmap(*entries):
    return {e.cve: e for e in entries}


def evidence(scope, kev, *, primary_age=hours(2), kev_age=hours(1), dating=True, now=NOW, kev_sha=None,
             primary_sha=None):
    vendor = scope.split(":")[0]
    sha = kev_ids_sha(kev) if primary_sha is None else primary_sha
    prim = SnapshotRef(source=PRIMARY[vendor], scope=scope, id=11, sha256="c" * 64,
                       fetched_at=now - primary_age, kev_ids_sha=sha)
    dat = tuple(SnapshotRef(source=s, scope=scope, id=20 + i, sha256="d" * 64, fetched_at=now - primary_age,
                            kev_ids_sha="") for i, s in enumerate(SCOPES[scope].dating_sources)) if dating else ()
    return Evidence(primary=prim, dating=dat,
                    kev=KevSnapshot(id=3, sha256="e" * 64, fetched_at=now - kev_age, catalog_version="2026.11.25",
                                    ids_sha=kev_ids_sha(kev) if kev_sha is None else kev_sha))


def host(rows, *, os=DEB12, mgr=None, kernel=None, meta=None, containerised=False, sha=SHA, posture=SHA,
         raw_rows=False):
    if mgr is None:
        mgr = "rpm" if os.id in ("rhel", "almalinux") else "dpkg"
    return HostInput(os=os, mgr=mgr, rows=rows if raw_rows else parse_rows(rows), kernel=kernel, meta=meta,
                     containerised=containerised, manifest_sha=sha, posture_manifest_sha=posture)


def kern_ok(package="linux-image-6.1.0-18-amd64", version="6.1.76-1", running="6.1.0-18-amd64", live=False):
    return KernelInfo(state="ok", running=running, package=package, package_version=version, livepatch=live)


def kern_unavailable(reason="unmanaged_kernel", live=False, running="6.1.0-18-amd64"):
    return KernelInfo(state="unavailable", reason=reason, running=running, livepatch=live)


def run(rows, fixes, kev, *, os=DEB12, scope=None, kernel=None, meta=None, now=NOW, ev=None, containerised=False,
        mgr=None, max_age=hours(48), sha=SHA, posture=SHA, scopes=None, **evkw):
    scope = scope or {"debian": "debian:" + (os.codename or ""), "ubuntu": "ubuntu:" + (os.codename or ""),
                      "rhel": "rhel:" + (os.version_id or "").split(".")[0],
                      "almalinux": "alma:" + (os.version_id or "").split(".")[0]}.get(os.id, "debian:bookworm")
    kev = kev if isinstance(kev, dict) else kevmap(*kev)
    if ev is None and scope in SCOPES:
        ev = evidence(scope, kev, now=now, **evkw)
    elif ev is None:
        ev = evidence("debian:bookworm", kev, now=now, **evkw)
    h = host(rows, os=os, kernel=kernel, meta=meta, containerised=containerised, mgr=mgr, sha=sha, posture=posture)
    return match_host(h, scopes=scopes or SCOPES, fixes=fixes, kev=kev, evidence=ev, now=now, max_age=max_age)


def row(name, evr, src=None, srcevr=None, arch="amd64"):
    return [name, evr, arch, src or name, srcevr or evr]


def open_of(res):
    return {(i.cve, i.pkg): i for i in res.open}


def unk_of(res):
    return {(i.cve, i.pkg): i.reason for i in res.unknown}


def leaf(res, n=14, at=NOW):
    return evaluate_leaf(res.to_data(), at, n)


# ------------------------------------------------------------------------------ fixture loaders
def load_kev_excerpt():
    j = json.loads((FIX / "kev.excerpt.json").read_text())
    out = {}
    for v in j["vulnerabilities"]:
        y, m, d = map(int, v["dateAdded"].split("-"))
        yy, mm, dd = map(int, v["dueDate"].split("-"))
        out[v["cveID"]] = KevEntry(cve=v["cveID"], date_added=D(y, m, d), first_seen_at=D(2026, 11, 1),
                                   due_date=dt.date(yy, mm, dd), ransomware=v["knownRansomwareCampaignUse"] == "Known")
    return out


_MON = {m: i + 1 for i, m in enumerate("Jan Feb Mar Apr May Jun Jul Aug Sep Oct Nov Dec".split())}


def load_dsa_dates():
    dates, cur = {}, None
    for line in (FIX / "DSA.excerpt.list").read_text().splitlines():
        m = re.match(r"^\[(\d\d) (\w{3}) (\d{4})\] ((?:DSA|DLA)-\S+) (\S+) ", line)
        if m:
            cur = (D(int(m.group(3)), _MON[m.group(2)], int(m.group(1))), m.group(4))
            continue
        m = re.match(r"^\t\[(\w+)\] - (\S+) (\S+)\s*$", line)
        if m and cur:
            dates.setdefault((m.group(1), m.group(2), m.group(3)), cur)
    return dates


def load_debian_fixes(release="bookworm", first=FIRST):
    tracker = json.loads((FIX / "debian-tracker.excerpt.json").read_text())
    dates = load_dsa_dates()
    out = []
    for pkg, cves in tracker.items():
        for cve, info in cves.items():
            r = info["releases"].get(release)
            if not r:
                continue
            st, fv = r["status"], r.get("fixed_version")
            scope = "debian:" + release
            if st == "resolved" and fv == "0":
                out.append(fixrow(cve, pkg, state="not_affected", scope=scope, first=first))
            elif st == "resolved":
                d = dates.get((release, pkg, fv))
                out.append(fixrow(cve, pkg, fv, at=d[0] if d else None, adv=d[1] if d else "", scope=scope, first=first))
            elif st == "open":
                out.append(fixrow(cve, pkg, state="open", scope=scope, first=first))
            else:
                out.append(fixrow(cve, pkg, state="undetermined", scope=scope, first=first))
    return out


def load_dpkg_query():
    rows = []
    for line in (FIX / "dpkg-query.bookworm.txt").read_text().splitlines():
        name, ver, arch, st, src, srcver = [p.strip() for p in line.split("\t")]
        if st.split()[0][-1:] == "i" or st.startswith(("ii", "hi")):
            rows.append([name, ver, arch, src or name, srcver or ver])
    return rows


def load_rpm_qa():
    rows = []
    for line in (FIX / "rpm-qa.alma9.txt").read_text().splitlines():
        name, epoch, ver, rel, arch, srpm = line.split("\t")
        ep = "" if epoch in ("", "0", "(none)") else epoch + ":"
        evr = "%s%s-%s" % (ep, ver, rel)
        bits = re.sub(r"\.(no)?src\.rpm$", "", srpm).rsplit("-", 2)
        rows.append([name, evr, arch, bits[0], "%s%s-%s" % (ep, bits[1], bits[2])])
    return rows


def load_os_samples():
    out, cur = {}, None
    for line in (FIX / "os-release.samples.txt").read_text().splitlines():
        if line.startswith("#"):
            cur = line[1:].strip().split(" (")[0]
            out[cur] = {}
        elif "=" in line and cur:
            k, v = line.split("=", 1)
            out[cur][k] = v.strip('"')
    res = {}
    for name, kv in out.items():
        res[name] = OsInfo(id=kv.get("ID"), version_id=kv.get("VERSION_ID"),
                           codename=kv.get("VERSION_CODENAME") or kv.get("UBUNTU_CODENAME"))
    return res


KEV = load_kev_excerpt()
DEB_FIXES = load_debian_fixes()
GLIBC_OLD = row("libc6", "2.36-9+deb12u2", "glibc", "2.36-9+deb12u2")
GLIBC_NEW = row("libc6", "2.36-9+deb12u10", "glibc", "2.36-9+deb12u10")
KEV_GLIBC_ADDED = D(2023, 11, 21)


# =============================================================================== 1. golden worked results
def test_fixture_loader_sanity():
    assert set(KEV) == {"CVE-2024-1086", "CVE-2023-4911"}
    g = [f for f in DEB_FIXES if f.pkg == "glibc"][0]
    assert (g.fixed_evr, g.fixed_at, g.advisory_id) == ("2.36-9+deb12u3", D(2023, 10, 3), "DSA-5514-1")
    k = [f for f in DEB_FIXES if f.pkg == "linux"][0]
    assert k.fixed_at is None                            # no DSA for a point-release kernel: undated (D6)


def test_golden_glibc_old_is_an_open_fix_and_the_clock_starts_at_the_kev_date():
    res = run([GLIBC_OLD], DEB_FIXES, KEV, kernel=kern_ok())
    assert res.status == "ok" and res.reason == "" and res.scope == "debian:bookworm"
    (it,) = res.open
    assert (it.cve, it.pkg, it.inst, it.fixed, it.adv) == ("CVE-2023-4911", "glibc", "2.36-9+deb12u2",
                                                           "2.36-9+deb12u3", "DSA-5514-1")
    assert it.basis == "advisory"
    assert it.fix_at == D(2023, 10, 3) and it.kev_at == KEV_GLIBC_ADDED     # clock_start = max = KEV date
    assert (it.due, it.ransom) == ("2023-12-12", False)
    assert res.unknown == () and res.no_fix == ()
    assert leaf(res).value is True


def test_golden_glibc_clock_is_the_kev_date_within_the_window_and_flips_after():
    res = run([GLIBC_OLD], DEB_FIXES, KEV, kernel=kern_ok())
    r5 = leaf(res, 14, KEV_GLIBC_ADDED + days(5))
    assert r5.value is False and r5.reason == ""
    assert r5.until == KEV_GLIBC_ADDED + days(14)                        # pending until clock_start + N
    assert leaf(res, 14, KEV_GLIBC_ADDED + days(15)).value is True


def test_golden_patched_glibc_has_no_items_and_holds():
    res = run([GLIBC_NEW], DEB_FIXES, KEV, kernel=kern_ok())
    assert res.status == "ok" and res.open == () and res.unknown == () and res.no_fix == ()
    r = leaf(res)
    assert r.value is False and r.reason == ""


def test_golden_undated_fix_first_seen_three_days_ago_is_unknown_not_a_pass():
    fx = [fixrow("CVE-2023-4911", "glibc", "2.36-9+deb12u3", first=NOW - days(3))]
    res = run([GLIBC_OLD], fx, KEV, kernel=kern_ok())
    (it,) = res.open
    assert it.basis == "first_seen" and it.fix_at == NOW - days(3)
    r = leaf(res)
    assert r.value is None and r.reason == "kev_undecided"
    assert r.undecided == 1 and r.definite == 0


def test_golden_undated_fix_first_seen_sixty_days_ago_is_a_proven_violation():
    fx = [fixrow("CVE-2023-4911", "glibc", "2.36-9+deb12u3", first=NOW - days(60))]
    res = run([GLIBC_OLD], fx, KEV, kernel=kern_ok())
    assert leaf(res).value is True                         # the fix is at least 60 days old


def test_golden_esm_tagged_version_is_unknown_esm_package():
    res = run([row("libc6", "2.36-9+deb12u2~esm1", "glibc", "2.36-9+deb12u2~esm1")], DEB_FIXES, KEV, kernel=kern_ok())
    assert unk_of(res) == {("CVE-2023-4911", "glibc"): "esm_package"} and res.open == ()
    r = leaf(res)
    assert r.value is None and r.reason == "esm_package"


KROWS = [row("linux-image-6.1.0-17-amd64", "6.1.69-1", "linux-signed-amd64", "6.1.69+1"),
         row("linux-image-6.1.0-18-amd64", "6.1.76-1", "linux-signed-amd64", "6.1.76+1")]
KFIX = [fixrow("CVE-2024-1086", "linux", "6.1.76-1", at=D(2024, 2, 1), adv="DSA-5600-1")]


def test_golden_kernel_running_old_with_the_fixed_kernel_installed_is_a_violation():
    res = run(KROWS, KFIX, KEV, kernel=kern_ok("linux-image-6.1.0-17-amd64", "6.1.69-1", "6.1.0-17-amd64"))
    (it,) = res.open
    assert (it.cve, it.pkg, it.inst, it.fixed) == ("CVE-2024-1086", "linux", "6.1.69-1", "6.1.76-1")
    assert it.kev_at == D(2024, 5, 30) and it.fix_at == D(2024, 2, 1)
    assert leaf(res).value is True                         # a reboot pending is a real exposure


def test_golden_kernel_running_fixed_holds():
    res = run(KROWS, KFIX, KEV, kernel=kern_ok())
    assert res.open == () and res.unknown == ()
    assert leaf(res).value is False and res.exact is True


def test_golden_kernel_livepatch_is_unknown_never_holds():
    res = run(KROWS, KFIX, KEV, kernel=kern_ok("linux-image-6.1.0-17-amd64", "6.1.69-1", "6.1.0-17-amd64", live=True))
    assert unk_of(res) == {("CVE-2024-1086", "linux"): "livepatch"} and res.open == ()
    r = leaf(res)
    assert r.value is None and r.reason == "livepatch"
    assert res.exact is False


def test_golden_kernel_undated_point_release_fix_is_unknown_inside_the_window():
    res = run(KROWS, DEB_FIXES, KEV, kernel=kern_ok("linux-image-6.1.0-17-amd64", "6.1.69-1", "6.1.0-17-amd64"))
    (it,) = res.open
    assert it.basis == "first_seen" and it.fix_at == FIRST
    assert leaf(res).value is None
    assert leaf(res, 14, FIRST + days(15)).value is True


def test_real_fixture_host_end_to_end():
    rows = load_dpkg_query()
    assert any(r[0] == "libc6" for r in rows)
    res = run(rows, DEB_FIXES, KEV, kernel=kern_ok("linux-image-6.1.0-18-amd64", "6.1.76-1", "6.1.0-18-amd64"))
    assert res.status == "ok"
    assert {(i.cve, i.pkg) for i in res.open} == {("CVE-2023-4911", "glibc")}      # libc6 2.36-9+deb12u2 is old
    assert res.unknown == ()                                                       # the running kernel is fixed


def test_openssh_is_flagged_only_when_its_cve_is_in_the_kev_set():
    rows = [row("openssh-server", "1:9.2p1-2+deb12u2", "openssh", "1:9.2p1-2+deb12u2")]
    assert run(rows, DEB_FIXES, KEV, kernel=kern_ok()).open == ()                  # CVE-2024-6387 is not in the KEV set
    k2 = dict(KEV, **{"CVE-2024-6387": kevrow("CVE-2024-6387", D(2024, 7, 5))})
    res = run(rows, DEB_FIXES, k2, kernel=kern_ok())
    (it,) = res.open
    assert (it.cve, it.fixed, it.adv, it.fix_at, it.kev_at) == ("CVE-2024-6387", "1:9.2p1-2+deb12u3", "DSA-5724-1",
                                                                D(2024, 7, 1), D(2024, 7, 5))


def test_open_state_without_a_fix_is_the_no_fix_bucket_not_a_violation():
    k2 = dict(KEV, **{"CVE-2026-123158": kevrow("CVE-2026-123158", D(2026, 11, 1))})
    rows = [row("openssh-server", "1:9.2p1-2+deb12u2", "openssh", "1:9.2p1-2+deb12u2")]
    res = run(rows, DEB_FIXES, k2, kernel=kern_ok())
    assert res.open == () and [(i.cve, i.pkg) for i in res.no_fix] == [("CVE-2026-123158", "openssh")]
    r = leaf(res)
    assert r.value is False and r.unfixed_count == 1
    assert "basis:no_fix_not_counted" in res.notes


# =============================================================================== 2. scope resolution
@pytest.mark.parametrize("os_,scope", [
    (DEB12, "debian:bookworm"), (OsInfo("debian", "13", "trixie"), "debian:trixie"),
    (UBU24, "ubuntu:noble"), (OsInfo("ubuntu", "22.04", "jammy"), "ubuntu:jammy"),
    (RHEL9, "rhel:9"), (OsInfo("rhel", "8.10", None), "rhel:8"), (ALMA9, "alma:9"), (OsInfo("almalinux", "8.9", None), "alma:8"),
])
def test_scope_resolution_supported(os_, scope):
    r = resolve_scope(os_, SCOPES, NOW)
    assert (r.status, r.scope, r.reason) == ("ok", scope, "")
    assert r.family == SCOPES[scope].family


@pytest.mark.parametrize("os_", [
    OsInfo("linuxmint", "21", "jammy"), OsInfo("raspbian", "12", "bookworm"), OsInfo("pop", "22.04", "jammy"),
    OsInfo("amzn", "2023", None), OsInfo("ol", "9.4", None), OsInfo("centos", "9", None), OsInfo("rocky", "9.4", None),
    OsInfo("sles", "15.5", None), OsInfo("opensuse-leap", "15.5", None), OsInfo("alpine", "3.19", None),
    OsInfo("fedora", "40", None), OsInfo("kali", "2024.1", "kali-rolling"), OsInfo("debian", "99", "nosuchcodename"),
    OsInfo("ubuntu", "20.10", "groovy"), OsInfo("rhel", "7.9", None), OsInfo("rhel", "x", None), OsInfo("rhel", "", None),
    OsInfo(None, None, None), OsInfo("Debian", "12", "bookworm"), OsInfo("debian ", "12", "bookworm"),
    OsInfo("almalinux", "٩.٥", None), OsInfo("rhel", "9x", None), OsInfo("rhel", "99999999999", None),
    OsInfo("debian", "12", None),
])
def test_derivatives_and_unknown_distros_are_distro_unsupported(os_):
    r = resolve_scope(os_, SCOPES, NOW)
    assert r.status == "unavailable" and r.reason == "distro_unsupported" and r.scope is None


def test_os_release_samples_including_the_mint_derivative():
    s = load_os_samples()
    assert resolve_scope(s["Debian 12"], SCOPES, NOW).scope == "debian:bookworm"
    assert resolve_scope(s["Ubuntu 24.04"], SCOPES, NOW).scope == "ubuntu:noble"
    assert resolve_scope(s["AlmaLinux 9"], SCOPES, NOW).scope == "alma:9"
    assert resolve_scope(s["RHEL 9"], SCOPES, NOW).scope == "rhel:9"
    mint = next(v for k, v in s.items() if k.startswith("Linux Mint"))
    assert mint.id == "linuxmint"
    assert resolve_scope(mint, SCOPES, NOW).reason == "distro_unsupported"     # ID_LIKE never maps (mutation: derivatives)


def test_eol_status_and_past_support_until_read_release_eol():
    eol = dict(SCOPES, **{"debian:bookworm": _scope("debian:bookworm", "deb", "debian", "bookworm", status="eol")})
    r = resolve_scope(DEB12, eol, NOW)
    assert (r.status, r.reason, r.scope) == ("unavailable", "release_eol", "debian:bookworm")
    past = dict(SCOPES, **{"debian:bookworm": _scope("debian:bookworm", "deb", "debian", "bookworm", until=NOW.date() - days(1))})
    assert resolve_scope(DEB12, past, NOW).reason == "release_eol"
    fut = dict(SCOPES, **{"debian:bookworm": _scope("debian:bookworm", "deb", "debian", "bookworm", until=NOW.date() + days(1))})
    assert resolve_scope(DEB12, fut, NOW).status == "ok"
    ext = dict(SCOPES, **{"debian:bookworm": _scope("debian:bookworm", "deb", "debian", "bookworm", status="extended")})
    assert resolve_scope(DEB12, ext, NOW).status == "ok"
    bad = dict(SCOPES, **{"debian:bookworm": _scope("debian:bookworm", "deb", "debian", "bookworm", status="weird")})
    assert resolve_scope(DEB12, bad, NOW).status == "unavailable"               # an unknown status is never "supported"


def test_a_scope_missing_from_the_table_is_distro_unsupported():
    only = {k: v for k, v in SCOPES.items() if k != "ubuntu:noble"}
    assert resolve_scope(UBU24, only, NOW).reason == "distro_unsupported"


def test_version_id_that_contradicts_the_codename_is_inconsistent():
    r = resolve_scope(OsInfo("ubuntu", "22.04", "noble"), SCOPES, NOW)
    assert r.status == "unavailable" and r.reason == "os_identity_inconsistent"
    assert resolve_scope(OsInfo("debian", "11", "bookworm"), SCOPES, NOW).reason == "os_identity_inconsistent"
    assert resolve_scope(OsInfo("ubuntu", "24.04.1", "noble"), SCOPES, NOW).status == "ok"
    assert resolve_scope(OsInfo("debian", None, "bookworm"), SCOPES, NOW).status == "ok"   # no version_id: nothing to contradict


def _drows(n, tag, base="pkg"):
    return [row("%s%d" % (base, i), "1.%d-1%s" % (i, tag)) for i in range(n)]


def test_identity_vote_more_than_half_of_tagged_packages_must_carry_the_claimed_release():
    res = resolve_scope(DEB12, SCOPES, NOW)
    ok = _drows(6, "+deb12u1") + _drows(5, "+deb11u2", "old") + [row("untagged", "1.0-1")] * 10
    assert check_identity(res, "dpkg", parse_rows(ok)) == ""
    tie = _drows(5, "+deb12u1") + _drows(5, "+deb11u2", "old")
    assert check_identity(res, "dpkg", parse_rows(tie)) == "os_identity_inconsistent"          # exactly 50 %: not more
    lie = _drows(2, "+deb12u1") + _drows(9, "+deb11u2", "old")
    assert check_identity(res, "dpkg", parse_rows(lie)) == "os_identity_inconsistent"
    assert check_identity(res, "dpkg", parse_rows([row("a", "1.0-1")])) == ""                  # no tags: no evidence either way


def test_identity_vote_ubuntu_and_rpm_tags_and_backports():
    ub = resolve_scope(UBU24, SCOPES, NOW)
    good = [row("a%d" % i, "1.0-0ubuntu0.24.04.%d" % (i + 1)) for i in range(4)] + [row("b", "2.0~22.04.1")]
    assert check_identity(ub, "dpkg", parse_rows(good)) == ""
    liar = [row("a%d" % i, "1.0-0ubuntu0.22.04.%d" % (i + 1)) for i in range(4)] + [row("b", "2.0~24.04.1")]
    assert check_identity(ub, "dpkg", parse_rows(liar)) == "os_identity_inconsistent"
    al = resolve_scope(ALMA9, SCOPES, NOW)
    arows = [row("p%d" % i, "1-1.el9_%d" % i, arch="x86_64") for i in range(3)] + [row("m", "1:1-1.module+el9.3.0+1+a", arch="x86_64")]
    assert check_identity(al, "rpm", parse_rows(arows)) == ""
    lie8 = [row("p%d" % i, "1-1.el8_%d" % i, arch="x86_64") for i in range(5)]
    assert check_identity(al, "rpm", parse_rows(lie8)) == "os_identity_inconsistent"
    bp = resolve_scope(DEB12, SCOPES, NOW)
    assert check_identity(bp, "dpkg", parse_rows([row("a", "1-1~bpo12+1"), row("b", "1-1+deb12u1")])) == ""


def test_package_manager_must_match_the_claimed_family():
    assert check_identity(resolve_scope(DEB12, SCOPES, NOW), "rpm", parse_rows([row("a", "1-1.el9")])) == "os_identity_inconsistent"
    assert check_identity(resolve_scope(ALMA9, SCOPES, NOW), "dpkg", parse_rows([row("a", "1.0-1")])) == "os_identity_inconsistent"


# =============================================================================== 3. gates: statuses and freshness
def test_unsupported_distro_and_eol_never_match():
    res = run([GLIBC_OLD], DEB_FIXES, KEV, os=OsInfo("linuxmint", "21", "jammy"), scope="debian:bookworm")
    assert (res.status, res.reason) == ("unavailable", "distro_unsupported")
    assert res.open == () and leaf(res).value is None                   # the empty data must not read as False
    eol = dict(SCOPES, **{"debian:bookworm": _scope("debian:bookworm", "deb", "debian", "bookworm", status="eol")})
    res = run([GLIBC_OLD], DEB_FIXES, KEV, scopes=eol)
    assert (res.status, res.reason) == ("unavailable", "release_eol")


def test_containerised_agent_is_unavailable():
    res = run([GLIBC_OLD], DEB_FIXES, KEV, containerised=True)
    assert (res.status, res.reason) == ("unavailable", "containerised_agent")


def test_missing_manifest_and_not_current_manifest_are_errors():
    h = HostInput(os=DEB12, mgr="dpkg", rows=None, kernel=kern_ok(), meta=None, containerised=False,
                  manifest_sha=SHA, posture_manifest_sha=SHA)
    ev = evidence("debian:bookworm", KEV)
    res = match_host(h, scopes=SCOPES, fixes=DEB_FIXES, kev=KEV, evidence=ev, now=NOW)
    assert (res.status, res.reason) == ("error", "manifest_missing")
    res = run([GLIBC_OLD], DEB_FIXES, KEV, kernel=kern_ok(), posture="cd" * 32)
    assert (res.status, res.reason) == ("error", "manifest_not_current")
    res = run([GLIBC_OLD], DEB_FIXES, KEV, kernel=kern_ok(), sha="")
    assert (res.status, res.reason) == ("error", "manifest_missing")


def test_malformed_rows_make_the_manifest_unusable_not_empty():
    assert parse_rows(None) is None
    for bad in ([["a", "1", "amd64", "a"]], [["a", "1", "amd64", "a", 5]], [["a", "1", "amd64", "a", "1"], "x"],
                "notalist", [["a" * 600, "1", "amd64", "a", "1"]], [[None, "1", "amd64", "a", "1"]]):
        assert parse_rows(bad) is None
    assert parse_rows([]) == ()
    assert parse_rows([list(r) for r in [GLIBC_OLD]]) is not None
    assert parse_rows([GLIBC_OLD] * 20001) is None                      # beyond the 8000-row contract by a wide margin


def test_stale_snapshots_are_advisory_stale_and_the_boundary_is_strict():
    res = run([GLIBC_OLD], DEB_FIXES, KEV, primary_age=hours(49))
    assert (res.status, res.reason) == ("error", "advisory_stale")
    assert run([GLIBC_OLD], DEB_FIXES, KEV, primary_age=hours(48)).status == "ok"
    assert run([GLIBC_OLD], DEB_FIXES, KEV, primary_age=hours(48) + dt.timedelta(seconds=1)).reason == "advisory_stale"
    res = run([GLIBC_OLD], DEB_FIXES, KEV, kev_age=hours(49))
    assert (res.status, res.reason) == ("error", "advisory_stale")
    assert run([GLIBC_OLD], DEB_FIXES, KEV, kev_age=hours(47)).status == "ok"


def test_the_staleness_limit_is_the_stricter_of_the_scope_and_the_setting():
    tight = dict(SCOPES, **{"debian:bookworm": ScopeInfo("debian:bookworm", "deb", "debian", "bookworm", "supported", None,
                                                          ("dsa", "dla"), 6 * 3600, ())})
    assert run([GLIBC_OLD], DEB_FIXES, KEV, scopes=tight, primary_age=hours(7)).reason == "advisory_stale"
    assert run([GLIBC_OLD], DEB_FIXES, KEV, scopes=tight, primary_age=hours(5)).status == "ok"
    assert run([GLIBC_OLD], DEB_FIXES, KEV, max_age=hours(3), primary_age=hours(4)).reason == "advisory_stale"


def test_missing_current_snapshot_is_advisory_stale_and_scope_mismatch_too():
    ev = evidence("debian:bookworm", KEV)
    for bad in (Evidence(primary=None, dating=ev.dating, kev=ev.kev), Evidence(primary=ev.primary, dating=ev.dating, kev=None)):
        res = run([GLIBC_OLD], DEB_FIXES, KEV, ev=bad)
        assert (res.status, res.reason) == ("error", "advisory_stale")
    wrong = Evidence(primary=SnapshotRef("debian-tracker", "debian:trixie", 11, "c" * 64, NOW - hours(1), kev_ids_sha(KEV)),
                     dating=ev.dating, kev=ev.kev)
    assert run([GLIBC_OLD], DEB_FIXES, KEV, ev=wrong).reason == "advisory_stale"


def test_a_snapshot_filtered_with_another_kev_set_is_advisory_behind_kev():
    res = run([GLIBC_OLD], DEB_FIXES, KEV, primary_sha=kev_ids_sha(["CVE-2023-4911"]))      # mutation: drop kev_ids_sha check
    assert (res.status, res.reason) == ("error", "advisory_behind_kev")
    assert leaf(res).value is None
    res = run([GLIBC_OLD], DEB_FIXES, KEV, primary_sha="")
    assert res.reason == "advisory_behind_kev"
    assert run([GLIBC_OLD], DEB_FIXES, KEV).status == "ok"


def test_kev_ids_sha_is_order_independent_and_sensitive():
    a = kev_ids_sha(["CVE-2024-1086", "CVE-2023-4911"])
    assert a == kev_ids_sha(["CVE-2023-4911", "CVE-2024-1086", "CVE-2024-1086"])
    assert a != kev_ids_sha(["CVE-2023-4911"])
    assert re.fullmatch(r"[0-9a-f]{64}", a)
    assert kev_ids_sha([]) == hashlib.sha256(b"").hexdigest()
    assert kev_ids_sha({"CVE-2024-1086": 1, "CVE-2023-4911": 2}) == a            # a mapping is its key set


def test_future_fetched_at_cannot_extend_validity():
    ev = evidence("debian:bookworm", KEV, primary_age=hours(-500), kev_age=hours(-500))
    res = run([GLIBC_OLD], DEB_FIXES, KEV, ev=ev)
    assert res.status == "ok"
    assert res.valid_until <= NOW + hours(48)                          # a fetch "in the future" counts as now


def test_valid_until_is_the_oldest_fetch_plus_the_limit_and_clamps_the_leaf():
    res = run([GLIBC_NEW], DEB_FIXES, KEV, kernel=kern_ok(), primary_age=hours(10), kev_age=hours(3))
    assert res.valid_until == NOW - hours(10) + hours(48)
    d = res.to_data()
    assert d["snap"]["valid_until"] == Z(NOW - hours(10) + hours(48))
    r = evaluate_leaf(d, NOW, 14)
    assert r.value is False and r.until == res.valid_until
    late = evaluate_leaf(d, res.valid_until + dt.timedelta(seconds=1), 14)
    assert late.value is None and late.reason == "advisory_stale"          # never False on stale evidence


def test_a_stale_or_missing_dating_source_makes_dated_rows_undated_not_unknown_hosts():
    res = run([GLIBC_OLD], DEB_FIXES, KEV, kernel=kern_ok(), dating=False)
    assert res.status == "ok"
    (it,) = res.open
    assert it.basis == "first_seen" and it.fix_at == FIRST                # dated fix demoted to our first sighting
    assert leaf(res).value is True                                         # KEV 2023 and first sighting 6 days ago? see below
    # the clock is max(first_seen 2026-11-20, kev 2023) = 2026-11-20, so inside 14 d it is undecided
    # (asserted precisely with an explicit now in the next test)


def test_dating_demotion_precise_clock():
    res = run([GLIBC_OLD], DEB_FIXES, KEV, kernel=kern_ok(), dating=False)
    assert evaluate_leaf(res.to_data(), NOW, 14).value is None
    assert evaluate_leaf(res.to_data(), FIRST + days(15), 14).value is True


# =============================================================================== 4. statements, dates, the clock
def test_not_affected_and_fixed_zero_never_flag():
    fx = [fixrow("CVE-2023-4911", "glibc", state="not_affected"), fixrow("CVE-2023-4911", "glibc", "0", at=D(2020, 1, 1))]
    res = run([GLIBC_OLD], fx, KEV, kernel=kern_ok())
    assert res.open == () and res.unknown == () and res.no_fix == ()


def test_fix_comparison_direction_installed_equal_or_newer_is_patched():
    for inst, expect_open in [("2.36-9+deb12u2", True), ("2.36-9+deb12u3", False), ("2.36-9+deb12u4", False),
                              ("2.36-9+deb12u10", False), ("2.35-1", True), ("1:1.0-1", False)]:
        res = run([row("libc6", inst, "glibc", inst)], DEB_FIXES, KEV, kernel=kern_ok())
        assert bool(res.open) is expect_open, inst


def test_irrelevant_packages_cannot_make_a_host_unknown():
    junk = [row("zzz", "v1.0-???"), row("yyy", "x" * 1000), row("curl", "1:" + "9" * 40 + "-1")]
    res = run([GLIBC_NEW] + junk, DEB_FIXES, KEV, kernel=kern_ok())
    assert res.unknown == () and res.open == ()
    assert leaf(res).value is False


def test_unparsable_installed_version_of_a_relevant_package_is_unknown_never_patched():
    for bad in ["v2.36-9", "١٢٣", "2.36-9-", "2.36" + "9" * 300, "2.36-9\n", "", "2.36 -9", "x2.36-9"]:
        res = run([row("libc6", bad, "glibc", bad)], DEB_FIXES, KEV, kernel=kern_ok())
        assert unk_of(res) == {("CVE-2023-4911", "glibc"): "version_unparsable"}, repr(bad)
        assert res.open == () and leaf(res).value is None


def test_unparsable_fixed_version_in_the_feed_is_unknown_when_nothing_else_is_unmet():
    fx = [fixrow("CVE-2023-4911", "glibc", "not a version")]
    res = run([GLIBC_OLD], fx, KEV, kernel=kern_ok())
    assert unk_of(res) == {("CVE-2023-4911", "glibc"): "version_unparsable"}


def test_resolved_row_without_a_fixed_version_is_unknown_undetermined():
    res = run([GLIBC_OLD], [fixrow("CVE-2023-4911", "glibc", "")], KEV, kernel=kern_ok())
    assert unk_of(res) == {("CVE-2023-4911", "glibc"): "undetermined"}


def test_undetermined_and_esm_only_statements_are_unknown():
    res = run([GLIBC_OLD], [fixrow("CVE-2023-4911", "glibc", state="undetermined")], KEV, kernel=kern_ok())
    assert unk_of(res) == {("CVE-2023-4911", "glibc"): "undetermined"}
    res = run([GLIBC_OLD], [fixrow("CVE-2023-4911", "glibc", "2.36-9+deb12u3", state="esm_only")], KEV, kernel=kern_ok())
    assert unk_of(res) == {("CVE-2023-4911", "glibc"): "esm_only_fix"}
    assert leaf(res).reason == "esm_only_fix"


def test_a_definite_violation_wins_over_unknown_statements_on_the_same_cve():
    fx = [fixrow("CVE-2023-4911", "glibc", "2.36-9+deb12u3", at=D(2023, 10, 3)),
          fixrow("CVE-2023-4911", "glibc", state="undetermined")]
    res = run([GLIBC_OLD], fx, KEV, kernel=kern_ok())
    assert list(open_of(res)) == [("CVE-2023-4911", "glibc")] and res.unknown == ()


def test_unknown_beats_the_no_fix_bucket_for_the_same_cve_and_package():
    fx = [fixrow("CVE-2023-4911", "glibc", state="open"), fixrow("CVE-2023-4911", "glibc", state="undetermined")]
    res = run([GLIBC_OLD], fx, KEV, kernel=kern_ok())
    assert unk_of(res) == {("CVE-2023-4911", "glibc"): "undetermined"} and res.no_fix == ()


def test_unknown_item_never_hides_another_cves_violation_and_the_leaf_says_true():
    fx = [fixrow("CVE-2023-4911", "glibc", "2.36-9+deb12u3", at=D(2023, 10, 3)),
          fixrow("CVE-2024-1086", "bash", state="undetermined")]
    res = run([GLIBC_OLD, row("bash", "5.2-1")], fx, KEV, kernel=kern_ok())
    assert len(res.open) == 1 and len(res.unknown) == 1
    r = leaf(res)
    assert r.value is True and r.definite == 1 and r.undecided == 1        # mutation: unknown beats a violation


def test_earliest_unmet_fix_date_is_the_exposure_start_across_streams():
    fx = [fixrow("CVE-2023-4911", "glibc", "2.36-9+deb12u3", at=D(2023, 10, 3), adv="DSA-1"),
          fixrow("CVE-2023-4911", "glibc", "2.36-9+deb12u5", at=D(2024, 3, 1), adv="DSA-2"),
          fixrow("CVE-2023-4911", "glibc", "2.36-9+deb12u1", at=D(2023, 1, 1), adv="DSA-0")]    # already met
    res = run([GLIBC_OLD], fx, KEV, kernel=kern_ok())
    (it,) = res.open
    assert it.fix_at == D(2023, 10, 3) and it.fixed == "2.36-9+deb12u3" and it.adv == "DSA-1"
    assert it.basis == "advisory"


def test_an_undated_unmet_fix_makes_the_clock_an_upper_bound_even_next_to_a_dated_one():
    kv = dict(KEV, **{"CVE-2023-4911": kevrow("CVE-2023-4911", D(2023, 11, 21))})
    fx = [fixrow("CVE-2023-4911", "glibc", "2.36-9+deb12u3", at=D(2026, 11, 22), adv="DSA-1", first=D(2026, 11, 22)),
          fixrow("CVE-2023-4911", "glibc", "2.36-9+deb12u4", at=None, first=D(2026, 11, 23))]
    res = run([GLIBC_OLD], fx, kv, kernel=kern_ok())
    (it,) = res.open
    assert it.basis == "first_seen"                    # the undated fix could be older than the dated one
    assert it.fix_at == D(2026, 11, 22)
    assert evaluate_leaf(res.to_data(), D(2026, 11, 24), 14).value is None


def test_dates_are_read_at_the_start_of_the_day_and_the_boundary_is_strictly_greater():
    fx = [fixrow("CVE-2023-4911", "glibc", "2.36-9+deb12u3", at=D(2023, 10, 3))]
    res = run([GLIBC_OLD], fx, KEV, kernel=kern_ok())
    (it,) = res.open
    assert Z(it.kev_at) == "2023-11-21T00:00:00Z"                         # mutation: end of day
    edge = KEV_GLIBC_ADDED + days(14)
    at_edge = evaluate_leaf(res.to_data(), edge, 14)
    assert at_edge.value is False and at_edge.until == edge               # exactly N days: NOT overdue (mutation: >=)
    just = evaluate_leaf(res.to_data(), edge + dt.timedelta(seconds=1), 14)
    assert just.value is True                                              # second precision, no floor
    assert evaluate_leaf(res.to_data(), edge, 0).value is True
    assert evaluate_leaf(res.to_data(), KEV_GLIBC_ADDED, 0).value is False
    assert evaluate_leaf(res.to_data(), KEV_GLIBC_ADDED + dt.timedelta(seconds=1), 0).value is True


def test_a_future_dated_advisory_is_clamped_to_first_sighting_and_cannot_delay_the_clock():
    fx = [fixrow("CVE-2023-4911", "glibc", "2.36-9+deb12u3", at=NOW + days(30), first=NOW - days(3))]
    res = run([GLIBC_OLD], fx, KEV, kernel=kern_ok())
    (it,) = res.open
    assert it.fix_at == NOW - days(3)                                      # mutation: drop the clamp
    assert it.basis == "first_seen"                                        # only an upper bound: never a pass
    r = leaf(res)
    assert r.value is None
    assert evaluate_leaf(res.to_data(), NOW + days(30), 14).value is True


def test_a_future_kev_date_added_is_clamped_to_first_sighting():
    kv = {"CVE-2023-4911": kevrow("CVE-2023-4911", NOW + days(30), first=NOW - days(3))}
    fx = [fixrow("CVE-2023-4911", "glibc", "2.36-9+deb12u3", at=D(2023, 10, 3))]
    res = run([GLIBC_OLD], fx, kv, kernel=kern_ok())
    (it,) = res.open
    assert it.kev_at == NOW - days(3) and it.basis == "first_seen"
    assert leaf(res).value is None
    assert evaluate_leaf(res.to_data(), NOW + days(30), 14).value is True


def test_an_old_undated_fix_does_not_make_a_recent_kev_listing_undecided():
    # fix first seen 60 d ago (upper bound), listed in KEV 5 d ago: the clock cannot start before the listing
    kv = {"CVE-2023-4911": kevrow("CVE-2023-4911", NOW - days(5), first=NOW - days(5))}
    fx = [fixrow("CVE-2023-4911", "glibc", "2.36-9+deb12u3", first=NOW - days(60))]
    res = run([GLIBC_OLD], fx, kv, kernel=kern_ok())
    (it,) = res.open
    assert it.basis == "advisory" and it.kev_at == NOW - days(5)
    r = leaf(res)
    assert r.value is False and r.until == NOW - days(5) + days(14)


def test_the_binding_component_decides_the_basis():
    kv = {"CVE-2023-4911": kevrow("CVE-2023-4911", D(2023, 11, 21), first=D(2023, 11, 22))}
    old = [fixrow("CVE-2023-4911", "glibc", "2.36-9+deb12u3", at=NOW - days(5), first=NOW - days(5))]
    res = run([GLIBC_OLD], old, kv, kernel=kern_ok())
    assert res.open[0].basis == "advisory"                                 # fix (binding, dated) beats an old KEV date
    und = [fixrow("CVE-2023-4911", "glibc", "2.36-9+deb12u3", first=NOW - days(5))]
    assert run([GLIBC_OLD], und, kv, kernel=kern_ok()).open[0].basis == "first_seen"


def test_removed_fix_rows_are_ignored_by_the_index():
    gone = Fix(scope="debian:bookworm", cve="CVE-2023-4911", pkg="glibc", pkg_kind="source", state="fixed",
               fixed_evr="2.36-9+deb12u3", first_seen_at=FIRST, removed=True)
    res = run([GLIBC_OLD], [gone], KEV, kernel=kern_ok())
    assert res.open == ()


def test_fix_rows_of_other_scopes_are_ignored():
    other = [Fix(scope="debian:trixie", cve="CVE-2023-4911", pkg="glibc", pkg_kind="source", state="fixed",
                 fixed_evr="9.9-1", first_seen_at=FIRST, fixed_at=D(2020, 1, 1))]
    assert run([GLIBC_OLD], other, KEV, kernel=kern_ok()).open == ()


def test_several_binaries_of_one_source_are_compared_individually_and_deduplicated():
    rows = [row("libc6", "2.36-9+deb12u3", "glibc", "2.36-9+deb12u3"), row("libc-bin", "2.36-9+deb12u2", "glibc", "2.36-9+deb12u2"),
            row("libc-dev-bin", "2.36-9+deb12u2", "glibc", "2.36-9+deb12u2")]
    res = run(rows, DEB_FIXES, KEV, kernel=kern_ok())
    assert [(i.cve, i.pkg) for i in res.open] == [("CVE-2023-4911", "glibc")]          # one item, not two
    assert res.open[0].inst == "2.36-9+deb12u2"                                         # a leftover older binary reads unpatched


def test_binary_kind_rows_match_by_binary_name_and_source_kind_by_source_name():
    fx = [fixrow("CVE-2023-4911", "libc6", "2.36-9+deb12u3", kind="binary", at=D(2023, 10, 3))]
    assert run([GLIBC_OLD], fx, KEV, kernel=kern_ok()).open[0].pkg == "libc6"
    fx2 = [fixrow("CVE-2023-4911", "libc6", "2.36-9+deb12u3", kind="source", at=D(2023, 10, 3))]
    assert run([GLIBC_OLD], fx2, KEV, kernel=kern_ok()).open == ()         # "libc6" is not a SOURCE name


def test_relevant_counts_distinct_matching_package_keys():
    rows = [GLIBC_OLD, row("libc-bin", "2.36-9+deb12u2", "glibc", "2.36-9+deb12u2"), row("bash", "5.2-1")]
    res = run(rows, DEB_FIXES, KEV, kernel=kern_ok())
    assert res.to_data()["counts"] == {"relevant": 1, "open_fix": 1, "no_fix": 0, "undecided": 0}


# =============================================================================== 5. the kernel rule
def test_kernel_compares_the_binary_version_not_the_source_version():
    # binary >= fixed but the signed source version looks older: must NOT flag
    ok = [row("linux-image-6.1.0-18-amd64", "6.1.76-1", "linux-signed-amd64", "6.1.5+1")]
    assert run(ok, KFIX, KEV, kernel=kern_ok()).open == ()
    # binary old but the signed source version looks new: MUST flag
    old = [row("linux-image-6.1.0-17-amd64", "6.1.69-1", "linux-signed-amd64", "6.1.99+1")]
    res = run(old, KFIX, KEV, kernel=kern_ok("linux-image-6.1.0-17-amd64", "6.1.69-1", "6.1.0-17-amd64"))
    assert [(i.pkg, i.inst) for i in res.open] == [("linux", "6.1.69-1")]


def test_only_the_running_kernel_counts_not_other_installed_images_headers_or_libc_dev():
    rows = KROWS + [row("linux-headers-6.1.0-17-amd64", "6.1.69-1", "linux", "6.1.69-1"),
                    row("linux-libc-dev", "6.1.69-1", "linux", "6.1.69-1"),
                    row("linux-perf", "6.1.69-1", "linux", "6.1.69-1"),
                    row("linux-image-amd64", "6.1.69-1", "linux-latest", "6.1.69-1")]
    res = run(rows, KFIX, KEV, kernel=kern_ok())                                  # running -18 (fixed)
    assert res.open == () and res.unknown == ()                                    # mutation: count installed, not running


def test_kernel_package_must_be_an_installed_row_with_the_reported_version():
    res = run(KROWS, KFIX, KEV, kernel=kern_ok("linux-image-6.1.0-99-amd64", "6.1.76-1", "6.1.0-99-amd64"))
    assert unk_of(res) == {("CVE-2024-1086", "linux"): "kernel_unknown"}           # "hide the kernel"
    res = run(KROWS, KFIX, KEV, kernel=kern_ok("linux-image-6.1.0-18-amd64", "9.9.9-1", "6.1.0-18-amd64"))
    assert unk_of(res) == {("CVE-2024-1086", "linux"): "kernel_unknown"}


def test_kernel_unavailable_or_unmanaged_makes_every_kernel_item_unknown():
    for k in (None, kern_unavailable(), kern_unavailable("no_data"), kern_unavailable(live=True)):
        res = run(KROWS, KFIX, KEV, kernel=k)
        assert unk_of(res) == {("CVE-2024-1086", "linux"): "kernel_unknown"}, k
        assert res.open == () and leaf(res).value is None
        assert res.exact is False


def test_a_host_with_no_kernel_package_and_no_kernel_info_is_unknown_not_a_pass():
    res = run([GLIBC_NEW], DEB_FIXES, KEV, kernel=kern_unavailable())
    assert [(i.cve, i.pkg, i.reason) for i in res.unknown] == [("CVE-2024-1086", "linux", "kernel_unknown")]
    assert leaf(res).value is None


def test_kernel_alias_maps_are_closed_hostile_names_do_not_map():
    for src in ("linux-signed-evil", "linux-evil", "linux-signed", "linuxx", "linux-signed-amd64x", "Linux", "linux ",
                "linux-latest-evil", "linux-signed-amd64-evil"):
        rows = [row("linux-image-6.1.0-18-amd64", "6.1.76-1", src, "6.1.76+1")]
        res = run(rows, KFIX, KEV, kernel=kern_ok())
        assert unk_of(res) == {("CVE-2024-1086", "linux"): "kernel_unknown"}, src      # unmapped: never a pass
    assert SC.debian_kernel_key("linux-signed-amd64") == "linux"
    assert SC.debian_kernel_key("linux") == "linux"
    assert SC.debian_kernel_key("linux-signed-evil") is None


def test_kernel_package_that_is_not_an_image_is_unknown():
    rows = [row("bash", "6.1.76-1", "linux", "6.1.76-1")]
    res = run(rows, KFIX, KEV, kernel=kern_ok("bash", "6.1.76-1", "6.1.0-18-amd64"))
    assert unk_of(res) == {("CVE-2024-1086", "linux"): "kernel_unknown"}


def test_ubuntu_kernel_flavour_aliases():
    assert SC.ubuntu_kernel_key("linux") == "linux"
    assert SC.ubuntu_kernel_key("linux-signed") == "linux"
    assert SC.ubuntu_kernel_key("linux-meta") == "linux"
    assert SC.ubuntu_kernel_key("linux-signed-aws") == "linux-aws"
    assert SC.ubuntu_kernel_key("linux-restricted-modules-azure") == "linux-azure"
    assert SC.ubuntu_kernel_key("linux-meta-hwe-6.8") is None or SC.ubuntu_kernel_key("linux-meta-hwe-6.8") == "linux-hwe-6.8"
    assert SC.ubuntu_kernel_key("linux-signed-hwe-22.04") == "linux-hwe-22.04"
    assert SC.ubuntu_kernel_key("linux-aws-6.8") == "linux-aws-6.8"
    for evil in ("linux-signed-evil", "linux-evil", "linux-aws-evil", "linuxsigned", "linux-signed-aws-evil", "linux--aws"):
        assert SC.ubuntu_kernel_key(evil) is None, evil


def test_ubuntu_kernel_matches_only_the_running_flavours_source():
    fx = [fixrow("CVE-2024-1086", "linux", "6.8.0-45.45", scope="ubuntu:noble", at=D(2024, 8, 1)),
          fixrow("CVE-2024-1086", "linux-aws", "6.8.0-1015.16", scope="ubuntu:noble", at=D(2024, 8, 1))]
    rows = [row("linux-image-6.8.0-1010-aws", "6.8.0-1010.10", "linux-signed-aws", "6.8.0-1010.10"),
            row("linux-image-6.8.0-40-generic", "6.8.0-40.40", "linux-signed", "6.8.0-40.40")]
    k = kern_ok("linux-image-6.8.0-1010-aws", "6.8.0-1010.10", "6.8.0-1010-aws")
    res = run(rows, fx, KEV, os=UBU24, kernel=k)
    assert [(i.pkg, i.inst, i.fixed) for i in res.open] == [("linux-aws", "6.8.0-1010.10", "6.8.0-1015.16")]   # generic ignored
    k2 = kern_ok("linux-image-6.8.0-40-generic", "6.8.0-40.40", "6.8.0-40-generic")
    res = run(rows, fx, KEV, os=UBU24, kernel=k2)
    assert [(i.pkg, i.inst) for i in res.open] == [("linux", "6.8.0-40.40")]


def test_rpm_running_kernel_is_the_only_one_judged_and_modules_are_ignored():
    fx = [fixrow("CVE-2024-1086", "kernel-core", "5.14.0-570.12.1.el9_6", scope="alma:9", at=D(2025, 5, 1)),
          fixrow("CVE-2024-1086", "kernel-modules", "5.14.0-570.12.1.el9_6", scope="alma:9", at=D(2025, 5, 1)),
          fixrow("CVE-2024-1086", "perf", "5.14.0-570.12.1.el9_6", scope="alma:9", at=D(2025, 5, 1))]
    rows = [row("kernel-core", "5.14.0-503.11.1.el9_5", "kernel", "5.14.0-503.11.1.el9_5", "x86_64"),
            row("kernel-core", "5.14.0-570.12.1.el9_6", "kernel", "5.14.0-570.12.1.el9_6", "x86_64"),
            row("kernel-modules", "5.14.0-503.11.1.el9_5", "kernel", "5.14.0-503.11.1.el9_5", "x86_64"),
            row("perf", "5.14.0-503.11.1.el9_5", "kernel", "5.14.0-503.11.1.el9_5", "x86_64")]
    old = kern_ok("kernel-core", "5.14.0-503.11.1.el9_5", "5.14.0-503.11.1.el9_5.x86_64")
    res = run(rows, fx, KEV, os=ALMA9, kernel=old)
    assert [(i.pkg, i.inst) for i in res.open] == [("kernel-core", "5.14.0-503.11.1.el9_5")]
    new = kern_ok("kernel-core", "5.14.0-570.12.1.el9_6", "5.14.0-570.12.1.el9_6.x86_64")
    res = run(rows, fx, KEV, os=ALMA9, kernel=new)
    assert res.open == () and res.unknown == () and leaf(res, 30).value is False
    res = run(rows, fx, KEV, os=ALMA9, kernel=kern_ok("kernel-core", "5.14.0-503.11.1.el9_5", "x", live=True))
    assert unk_of(res) == {("CVE-2024-1086", "kernel-core"): "livepatch"}


def test_rpm_kernel_package_outside_the_closed_name_set_is_kernel_unknown():
    fx = [fixrow("CVE-2024-1086", "kernel-core", "5.14.0-570.12.1.el9_6", scope="alma:9", at=D(2025, 5, 1))]
    rows = [row("kernel-core", "5.14.0-503.11.1.el9_5", "kernel", "5.14.0-503.11.1.el9_5", "x86_64"),
            row("bash", "5.1-1.el9", "bash", "5.1-1.el9", "x86_64")]
    res = run(rows, fx, KEV, os=ALMA9, kernel=kern_ok("bash", "5.1-1.el9", "x"))
    assert unk_of(res) == {("CVE-2024-1086", "kernel-core"): "kernel_unknown"}


# =============================================================================== 6. rpm: modular, foreign, meta, notes
ALMA_KEV = {"CVE-2022-32893": kevrow("CVE-2022-32893", D(2022, 8, 18)), "CVE-2023-4911": kevrow("CVE-2023-4911", D(2023, 11, 21))}


def load_alma_fixes(first=FIRST):
    out = []
    for e in json.loads((FIX / "alma9-errata.excerpt.json").read_text()):
        when = dt.datetime.fromtimestamp(e["issued_date"]["$date"] / 1000, tz=UTC)
        cves = [r["id"] for r in e["references"] if r["type"] == "cve"]
        for p in e["pkglist"]["packages"]:
            if p["arch"] == "src" or p["name"].endswith("-debuginfo"):
                continue
            evr = ("%s:" % p["epoch"] if p["epoch"] not in ("0", "", None) else "") + "%s-%s" % (p["version"], p["release"])
            for cve in cves:
                out.append(fixrow(cve, p["name"], evr, at=when, adv=e["updateinfo_id"], scope="alma:9", first=first))
    return out


ALMA_FIXES = load_alma_fixes()


def test_alma_fixture_loader_and_rpm_match():
    assert any(f.pkg == "webkit2gtk3" and f.fixed_at == D(2022, 9, 20) for f in ALMA_FIXES)
    rows = [row("webkit2gtk3", "2.36.3-1.el9", "webkit2gtk3", "2.36.3-1.el9", "x86_64")]
    res = run(rows, ALMA_FIXES, ALMA_KEV, os=ALMA9, kernel=kern_unavailable())
    (it,) = res.open
    assert (it.cve, it.pkg, it.fixed, it.adv, it.fix_at, it.kev_at) == ("CVE-2022-32893", "webkit2gtk3", "2.36.7-1.el9_0",
                                                                        "ALSA-2022:6634", D(2022, 9, 20), D(2022, 8, 18))
    assert it.basis == "advisory" and leaf(res, 30).value is True
    new = [row("webkit2gtk3", "2.36.7-1.el9_0", "webkit2gtk3", "2.36.7-1.el9_0", "x86_64")]
    assert run(new, ALMA_FIXES, ALMA_KEV, os=ALMA9, kernel=kern_unavailable()).open == ()


def test_real_rpm_qa_fixture_is_parsed_and_modular_nodejs_is_unknown():
    rows = load_rpm_qa()
    fx = [fixrow("CVE-2023-4911", "nodejs", "1:18.19.1-1.module+el9.4.0+1+abcd", scope="alma:9", at=D(2024, 1, 1)),
          fixrow("CVE-2023-4911", "glibc", "2.34-125.el9_5.1.alma.1", scope="alma:9", at=D(2024, 1, 1))]
    res = run(rows, fx, ALMA_KEV, os=ALMA9, kernel=kern_ok("kernel-core", "5.14.0-503.11.1.el9_5", "x"))
    assert unk_of(res) == {("CVE-2023-4911", "nodejs"): "modular_package"}      # glibc is current, nodejs is not comparable
    assert res.open == ()


@pytest.mark.parametrize("meta,reason", [
    (HostMeta(foreign=frozenset({"openssl-libs"}), modular=frozenset(), apt_origins=None), "foreign_signature"),
    (HostMeta(foreign=frozenset(), modular=frozenset({"openssl-libs"}), apt_origins=None), "modular_package"),
])
def test_rpm_meta_foreign_and_modular_names_are_unknown_when_relevant(meta, reason):
    fx = [fixrow("CVE-2023-4911", "openssl-libs", "1:3.2.2-6.el9_5.2", scope="alma:9", at=D(2024, 1, 1))]
    rows = [row("openssl-libs", "1:3.2.2-6.el9_5.1", "openssl", "1:3.2.2-6.el9_5.1", "x86_64")]
    res = run(rows, fx, ALMA_KEV, os=ALMA9, kernel=kern_unavailable(), meta=meta)
    assert unk_of(res) == {("CVE-2023-4911", "openssl-libs"): reason} and res.open == ()
    irrelevant = HostMeta(foreign=frozenset({"some-vendor-agent"}), modular=frozenset(), apt_origins=None)
    res = run(rows, fx, ALMA_KEV, os=ALMA9, kernel=kern_unavailable(), meta=irrelevant)
    assert [i.cve for i in res.open] == ["CVE-2023-4911"] and res.unknown == ()


def test_modular_advisory_rows_are_not_compared_against_plain_packages():
    fx = [fixrow("CVE-2023-4911", "nodejs", "1:18.19.1-1.el9", scope="alma:9", at=D(2024, 1, 1), modular=True)]
    rows = [row("nodejs", "1:16.0-1.el9", "nodejs", "1:16.0-1.el9", "x86_64")]
    res = run(rows, fx, ALMA_KEV, os=ALMA9, kernel=kern_unavailable())
    assert unk_of(res) == {("CVE-2023-4911", "nodejs"): "modular_package"} and res.open == ()


def test_rpm_drops_src_debuginfo_debugsource_and_gpg_pubkey_rows():
    fx = [fixrow("CVE-2023-4911", "glibc", "2.34-999.el9", scope="alma:9", at=D(2024, 1, 1)),
          fixrow("CVE-2023-4911", "glibc-debuginfo", "2.34-999.el9", scope="alma:9", at=D(2024, 1, 1)),
          fixrow("CVE-2023-4911", "glibc-debugsource", "2.34-999.el9", scope="alma:9", at=D(2024, 1, 1)),
          fixrow("CVE-2023-4911", "gpg-pubkey", "1-1.el9", scope="alma:9", at=D(2024, 1, 1))]
    rows = [row("glibc-debuginfo", "2.34-1.el9", arch="x86_64"), row("glibc-debugsource", "2.34-1.el9", arch="x86_64"),
            row("glibc", "2.34-1.el9", "glibc", "2.34-1.el9", "src"), row("gpg-pubkey", "1-1.el8", arch="noarch")]
    res = run(rows, fx, ALMA_KEV, os=ALMA9, kernel=kern_unavailable())
    assert res.open == () and res.unknown == () and res.to_data()["counts"]["relevant"] == 0


def test_rpm_multiple_streams_flag_a_host_below_any_unmet_fix():
    fx = [fixrow("CVE-2023-4911", "openssl-libs", "1:3.0.7-27.el9_4.1", scope="alma:9", at=D(2024, 2, 1), adv="A-1"),
          fixrow("CVE-2023-4911", "openssl-libs", "1:3.2.2-6.el9_5.2", scope="alma:9", at=D(2024, 11, 1), adv="A-2")]
    rows = [row("openssl-libs", "1:3.2.2-6.el9_5.1", "openssl", "1:3.2.2-6.el9_5.1", "x86_64")]
    res = run(rows, fx, ALMA_KEV, os=ALMA9, kernel=kern_unavailable())
    (it,) = res.open
    assert (it.fixed, it.adv, it.fix_at) == ("1:3.2.2-6.el9_5.2", "A-2", D(2024, 11, 1))   # only the unmet one counts


def test_rhel_gets_the_standard_stream_note_and_alma_does_not():
    fx = [fixrow("CVE-2023-4911", "openssl-libs", "1:3.2.2-6.el9_5.2", scope="rhel:9", at=D(2024, 1, 1))]
    rows = [row("openssl-libs", "1:3.2.2-6.el9_5.1", "openssl", "1:3.2.2-6.el9_5.1", "x86_64")]
    res = run(rows, fx, ALMA_KEV, os=RHEL9, kernel=kern_unavailable())
    assert "basis:rhel_standard_stream_assumed" in res.notes
    fx2 = [dataclass_replace(f, scope="alma:9") for f in fx]
    assert "basis:rhel_standard_stream_assumed" not in run(rows, fx2, ALMA_KEV, os=ALMA9, kernel=kern_unavailable()).notes


def dataclass_replace(obj, **kw):
    import dataclasses
    return dataclasses.replace(obj, **kw)


def test_notes_are_fixed_ordered_and_conditional():
    base = ["basis:distro_packages_only", "basis:installed_versions", "basis:advisory_feed_tls_only"]
    res = run([GLIBC_NEW], DEB_FIXES, KEV, kernel=kern_ok())
    assert list(res.notes[:3]) == base
    assert "basis:package_origin_unverified" in res.notes            # deb origin is never provable per package
    meta = HostMeta(foreign=frozenset(), modular=frozenset(), apt_origins=("o=Debian,a=stable,n=bookworm",))
    res = run([GLIBC_NEW], DEB_FIXES, KEV, kernel=kern_ok(), meta=meta)
    assert res.third_party_sources is False and "basis:third_party_repositories_present" not in res.notes
    meta = HostMeta(foreign=frozenset(), modular=frozenset(), apt_origins=("o=Debian,a=stable", "o=Docker,a=bookworm"))
    res = run([GLIBC_NEW], DEB_FIXES, KEV, kernel=kern_ok(), meta=meta)
    assert res.third_party_sources is True and "basis:third_party_repositories_present" in res.notes
    assert list(res.notes) == sorted(res.notes, key=SC.NOTE_ORDER.index)
    # rpm: the note is only for a host without meta
    rrows = [row("glibc", "2.34-1.el9", arch="x86_64")]
    assert "basis:package_origin_unverified" in run(rrows, [], ALMA_KEV, os=ALMA9, kernel=kern_unavailable()).notes
    m2 = HostMeta(foreign=frozenset(), modular=frozenset(), apt_origins=None)
    res = run(rrows, [], ALMA_KEV, os=ALMA9, kernel=kern_unavailable(), meta=m2)
    assert "basis:package_origin_unverified" not in res.notes and res.third_party_sources is False
    m3 = HostMeta(foreign=frozenset({"x"}), modular=frozenset(), apt_origins=None)
    assert run(rrows, [], ALMA_KEV, os=ALMA9, kernel=kern_unavailable(), meta=m3).third_party_sources is True


@pytest.mark.parametrize("origins,expect", [
    ((), False), (("o=Debian,a=stable,n=bookworm,l=Debian",), False), (("o=Debian,a=stable-security",), False),
    (("o=Debian Backports,a=bookworm-backports",), False), (("garbage",), True), (("o=Evil",), True),
    (("a=stable",), True), (("o=Debian,a=stable", "o=Grafana"), True), (("O=Debian",), True),
])
def test_apt_origin_allow_list_is_closed(origins, expect):
    meta = HostMeta(foreign=frozenset(), modular=frozenset(), apt_origins=origins)
    assert run([GLIBC_NEW], DEB_FIXES, KEV, kernel=kern_ok(), meta=meta).third_party_sources is expect


def test_third_party_sources_is_none_without_meta():
    assert run([GLIBC_NEW], DEB_FIXES, KEV, kernel=kern_ok()).third_party_sources is None
    assert run([GLIBC_NEW], DEB_FIXES, KEV, kernel=kern_ok()).to_data()["third_party_sources"] is None


# =============================================================================== 7. the leaf
def _vu():
    return Z(NOW + days(1))


def mkdata(open_=(), *, unknown=(), unknown_total=None, truncated=False, open_total=None, no_fix_total=0, valid_until=None,
           reasons=None, v=1):
    unknown = list(unknown)
    ut = len(unknown) if unknown_total is None else unknown_total
    if reasons is None:
        reasons = {}
        for u in unknown:
            reasons[u["reason"]] = reasons.get(u["reason"], 0) + 1
        if ut > len(unknown):
            reasons["kernel_unknown"] = reasons.get("kernel_unknown", 0) + ut - len(unknown)
    return {"v": v, "scope": "debian:bookworm", "manifest": {"sha256": SHA, "count": 3},
            "snap": {"valid_until": valid_until or _vu()},
            "counts": {"relevant": 1, "open_fix": len(open_) if open_total is None else open_total, "no_fix": no_fix_total,
                       "undecided": ut},
            "open": list(open_), "open_truncated": truncated, "unknown": unknown, "unknown_total": ut,
            "unknown_reasons": reasons, "no_fix": [], "no_fix_total": no_fix_total, "third_party_sources": None, "notes": []}


def oi(cve="CVE-2023-4911", fix_at="2023-10-03T00:00:00Z", kev_at="2023-11-21T00:00:00Z", basis="advisory", pkg="glibc"):
    return {"cve": cve, "pkg": pkg, "inst": "1-1", "fixed": "2-1", "adv": "DSA-1", "fix_at": fix_at, "basis": basis,
            "kev_at": kev_at, "due": None, "ransom": False}


def ui(reason="esm_package", cve="CVE-2024-1", pkg="x"):
    return {"cve": cve, "pkg": pkg, "reason": reason}


def test_leaf_truth_table():
    assert evaluate_leaf(mkdata(), NOW, 14).value is False
    assert evaluate_leaf(mkdata([oi()]), NOW, 14).value is True
    assert evaluate_leaf(mkdata([oi(kev_at=Z(NOW - days(3)))]), NOW, 14).value is False                 # pending
    assert evaluate_leaf(mkdata([oi(kev_at=Z(NOW - days(3)), basis="first_seen")]), NOW, 14).value is None   # undecided
    assert evaluate_leaf(mkdata([oi(kev_at=Z(NOW - days(30)), basis="first_seen")]), NOW, 14).value is True
    assert evaluate_leaf(mkdata(unknown=[ui()]), NOW, 14).value is None
    assert evaluate_leaf(mkdata([oi()], unknown=[ui()]), NOW, 14).value is True                          # violation wins
    assert evaluate_leaf(mkdata(no_fix_total=3), NOW, 14).value is False


def test_leaf_never_reads_false_when_the_open_list_is_truncated():
    pend = [oi(cve="CVE-2024-%04d" % i, kev_at=Z(NOW - days(1))) for i in range(5)]
    assert evaluate_leaf(mkdata(pend, truncated=False), NOW, 14).value is False
    r = evaluate_leaf(mkdata(pend, truncated=True, open_total=105), NOW, 14)
    assert r.value is None and r.reason == "kev_undecided"                                               # mutation: ignore open_truncated
    over = [oi()] + pend
    assert evaluate_leaf(mkdata(over, truncated=True, open_total=106), NOW, 14).value is True


def test_leaf_unknown_total_counts_beyond_the_listed_cap():
    r = evaluate_leaf(mkdata(unknown=[], unknown_total=70), NOW, 14)
    assert r.value is None and r.undecided == 70


def test_leaf_reason_is_the_single_shared_reason_else_kev_undecided():
    r = evaluate_leaf(mkdata(unknown=[ui("livepatch"), ui("livepatch", cve="CVE-2024-2")]), NOW, 14)
    assert (r.value, r.reason) == (None, "livepatch")
    r = evaluate_leaf(mkdata(unknown=[ui("livepatch"), ui("esm_package", cve="CVE-2024-2")]), NOW, 14)
    assert (r.value, r.reason) == (None, "kev_undecided")
    r = evaluate_leaf(mkdata([oi(kev_at=Z(NOW - days(1)), basis="first_seen")], unknown=[ui("livepatch")]), NOW, 14)
    assert (r.value, r.reason) == (None, "kev_undecided")                                                # a clock item undecided too


def test_leaf_until_is_the_earliest_flip_by_the_clock():
    soon = oi(cve="CVE-2024-1", kev_at=Z(NOW - days(10)))          # flips at NOW + 4 d
    later = oi(cve="CVE-2024-2", kev_at=Z(NOW - days(2)))
    r = evaluate_leaf(mkdata([later, soon]), NOW, 14)
    assert r.value is False and r.until == NOW + days(4)
    r = evaluate_leaf(mkdata([later], valid_until=Z(NOW + days(1))), NOW, 14)
    assert r.until == NOW + days(1)                                 # the snapshot validity clamps it
    assert evaluate_leaf(mkdata([oi()]), NOW, 14).until is None     # a violation has no expiry
    assert evaluate_leaf(mkdata(unknown=[ui()]), NOW, 14).until is None


def test_leaf_n_must_be_an_int_in_range():
    for bad in (-1, 3651, 1.5, "14", None, True):
        with pytest.raises(ValueError):
            evaluate_leaf(mkdata(), NOW, bad)
    assert evaluate_leaf(mkdata(), NOW, 0).value is False
    assert evaluate_leaf(mkdata(), NOW, 3650).value is False


def test_leaf_counts_and_worst_item():
    a, b = oi(cve="CVE-2024-0002", kev_at="2024-02-01T00:00:00Z"), oi(cve="CVE-2024-0001", kev_at="2024-01-01T00:00:00Z")
    r = evaluate_leaf(mkdata([a, b, oi(cve="CVE-2025-1", kev_at=Z(NOW - days(1)))]), NOW, 14)
    assert (r.definite, r.pending, r.undecided) == (2, 1, 0)
    assert r.worst["cve"] == "CVE-2024-0001"                       # the most overdue (earliest clock start)
    assert r.more == 1                                              # other overdue items
    assert r.open_count == 3 and r.undecided_count == 0 and r.unfixed_count == 0


def test_leaf_open_count_is_known_only_when_nothing_is_undecided_or_truncated():
    assert evaluate_leaf(mkdata([oi()]), NOW, 14).open_count == 1
    assert evaluate_leaf(mkdata([oi()], unknown=[ui()]), NOW, 14).open_count is None
    assert evaluate_leaf(mkdata([oi()], truncated=True, open_total=101), NOW, 14).open_count is None
    r = evaluate_leaf(mkdata([oi()], unknown=[ui()]), NOW, 14)
    assert r.undecided_count == 1


@pytest.mark.parametrize("mut", [
    lambda d: d.pop("snap"), lambda d: d.update(v=2), lambda d: d.update(v=True), lambda d: d.update(open="x"),
    lambda d: d["open"].append({"cve": "x"}), lambda d: d["open"][0].update(fix_at="yesterday"),
    lambda d: d["open"][0].update(kev_at=None), lambda d: d["open"][0].update(basis="guess"),
    lambda d: d["open"][0].update(fix_at="2023-10-03T00:00:00+02:00"), lambda d: d.update(open_truncated="no"),
    lambda d: d.update(unknown_total=-1), lambda d: d.update(unknown_total=1.5), lambda d: d["snap"].update(valid_until="x"),
    lambda d: d.update(counts={"relevant": 1}), lambda d: d["counts"].update(open_fix=0),     # 1 listed, 0 counted
    lambda d: d.update(unknown_total=0, unknown=[ui()]),                                     # listed more than the total
    lambda d: d.update(open_truncated=False, counts=dict(d["counts"], open_fix=9)),           # not truncated yet counts differ
])
def test_malformed_fact_data_is_unknown_never_false(mut):
    d = mkdata([oi(kev_at=Z(NOW - days(1)))])
    mut(d)
    r = evaluate_leaf(d, NOW, 14)
    assert r.value is None and r.reason == "kev_undecided"


def test_leaf_accepts_deep_frozen_facts():
    def freeze(x):
        if isinstance(x, dict):
            return MappingProxyType({k: freeze(v) for k, v in x.items()})
        if isinstance(x, list):
            return tuple(freeze(v) for v in x)
        return x
    d = mkdata([oi(kev_at=Z(NOW - days(1)))], unknown=[ui()])
    assert evaluate_leaf(freeze(d), NOW, 14) == evaluate_leaf(d, NOW, 14)
    assert evaluate_leaf(freeze(mkdata()), NOW, 14).value is False


def test_leaf_data_without_status_ok_shape_is_unknown():
    for d in ({}, {"v": 1}, {"v": 1, "scope": "x"}, None, [], "x", 5):
        assert evaluate_leaf(d, NOW, 14).value is None


def test_leaf_now_must_be_aware():
    with pytest.raises(ValueError):
        evaluate_leaf(mkdata(), dt.datetime(2026, 1, 1), 14)


def test_describe_worst_is_short_restricted_and_names_the_more_count():
    r = evaluate_leaf(mkdata([oi(cve="CVE-2024-0001", kev_at="2024-01-01T00:00:00Z"),
                              oi(cve="CVE-2024-0002", kev_at="2024-02-01T00:00:00Z")]), NOW, 14)
    s = LEAF.describe_worst(r)
    assert s.startswith("CVE-2024-0001 glibc 1-1<2-1 fix 2023-10-03 kev 2024-01-01") and s.endswith("+1 more")
    assert len(s) <= 120 and re.fullmatch(r"[A-Za-z0-9 .+~:<>_,=/-]*", s)
    d = mkdata([dict(oi(), pkg="pkg\n\x00<script>" + "x" * 300, inst="v" * 300)])
    s2 = LEAF.describe_worst(evaluate_leaf(d, NOW, 14))
    assert len(s2) <= 120 and re.fullmatch(r"[A-Za-z0-9 .+~:<>_,=/?-]*", s2) and "\n" not in s2
    assert LEAF.describe_worst(evaluate_leaf(mkdata(), NOW, 14)) == ""


# =============================================================================== 8. the fact data and its caps
def many_rows(n_open=0, n_unknown=0, n_nofix=0):
    rows, fixes, kev = [], [], {}
    k = 0
    for n, kind in ((n_open, "open"), (n_unknown, "unknown"), (n_nofix, "nofix")):
        for i in range(n):
            k += 1
            name, cve = "p%04d" % k, "CVE-2020-%04d" % k
            kev[cve] = kevrow(cve, D(2021, 1, 1) + days(k % 400))
            if kind == "open":
                rows.append(row(name, "0.1-1"))
                fixes.append(fixrow(cve, name, "1.0-1", at=D(2021, 1, 1)))
            elif kind == "unknown":
                rows.append(row(name, "0.1-1~esm1"))
                fixes.append(fixrow(cve, name, "1.0-1", at=D(2021, 1, 1)))
            else:
                rows.append(row(name, "0.1-1"))
                fixes.append(fixrow(cve, name, state="open"))
    return rows, fixes, kev


def test_caps_sorting_and_size_for_a_hostile_host():
    rows, fixes, kev = many_rows(250, 120, 90)
    res = run(rows, fixes, kev, kernel=kern_ok())
    d = res.to_data()
    assert len(d["open"]) == 100 and d["open_truncated"] is True and d["counts"]["open_fix"] == 250
    keys = [(o["kev_at"] if o["kev_at"] > o["fix_at"] else o["fix_at"], o["cve"]) for o in d["open"]]
    assert keys == sorted(keys)                                              # clock_start ascending, then cve
    assert len(d["unknown"]) == 50 and d["unknown_total"] == 120 and d["unknown_reasons"] == {"esm_package": 120}
    assert len(d["no_fix"]) == 50 and d["no_fix_total"] == 90
    assert d["counts"] == {"relevant": 460, "open_fix": 250, "no_fix": 90, "undecided": 120}
    blob = json.dumps(d, sort_keys=True, separators=(",", ":"))
    assert len(blob) < 64 * 1024
    assert leaf(res).value is True                                           # truncated, but a kept item is overdue


def test_truncated_pending_only_host_is_unknown_in_the_leaf():
    rows, fixes, kev = many_rows(130, 0, 0)
    res = run(rows, fixes, kev, kernel=kern_ok())
    assert res.to_data()["open_truncated"] is True
    r = evaluate_leaf(res.to_data(), D(2021, 1, 2), 3650)                    # nothing overdue under a 10 year window
    assert r.value is None


def test_the_most_overdue_items_are_the_ones_kept():
    rows, fixes, kev = many_rows(150, 0, 0)
    res = run(rows, fixes, kev, kernel=kern_ok())
    kept = {(o["cve"]) for o in res.to_data()["open"]}
    starts = sorted((max(i.fix_at, i.kev_at), i.cve) for i in res.open)
    assert kept == {c for _, c in starts[:100]}


def test_data_has_the_contract_keys_no_floats_and_sorted_deterministic_lists():
    res = run([GLIBC_OLD], DEB_FIXES, KEV, kernel=kern_ok())
    d = res.to_data()
    assert list(d) == ["v", "scope", "manifest", "snap", "counts", "open", "open_truncated", "unknown", "unknown_total",
                       "unknown_reasons", "no_fix", "no_fix_total", "third_party_sources", "notes"]
    assert d["v"] == 1 and d["scope"] == "debian:bookworm" and d["manifest"] == {"sha256": SHA, "count": 1}
    assert d["open"][0] == {"cve": "CVE-2023-4911", "pkg": "glibc", "inst": "2.36-9+deb12u2", "fixed": "2.36-9+deb12u3",
                            "adv": "DSA-5514-1", "fix_at": "2023-10-03T00:00:00Z", "basis": "advisory",
                            "kev_at": "2023-11-21T00:00:00Z", "due": "2023-12-12", "ransom": False}
    assert d["snap"]["primary"] == {"id": 11, "sha12": "c" * 12, "fetched_at": Z(NOW - hours(2))}
    assert d["snap"]["kev"] == {"id": 3, "sha12": "e" * 12, "catalog": "2026.11.25", "fetched_at": Z(NOW - hours(1))}
    assert [x["source"] for x in d["snap"]["dating"]] == ["dla", "dsa"]          # sorted by source
    assert d["snap"]["valid_until"] == Z(NOW - hours(2) + hours(48))

    def walk(x):
        if isinstance(x, dict):
            assert all(isinstance(k, str) for k in x)
            for v in x.values():
                walk(v)
        elif isinstance(x, list):
            for v in x:
                walk(v)
        else:
            assert not isinstance(x, float)
    walk(d)
    json.dumps(d)


def test_non_ok_results_carry_minimal_data_that_the_leaf_never_reads_as_a_pass():
    res = run([GLIBC_OLD], DEB_FIXES, KEV, kernel=kern_ok(), primary_age=hours(60))
    assert res.status == "error"
    d = res.to_data()
    assert d["v"] == 1 and "open" not in d
    assert evaluate_leaf(d, NOW, 14).value is None


def test_evidence_tail_names_manifest_and_snapshots():
    res = run([GLIBC_OLD], DEB_FIXES, KEV, kernel=kern_ok())
    t = res.evidence_tail()
    assert t.startswith("kev:" + SHA[:12] + "|adv:") and "|kev:3:" + "e" * 12 in t and "c" * 12 in t
    assert len(t) < 200 and re.fullmatch(r"[A-Za-z0-9:|+._-]+", t)


# =============================================================================== 9. determinism, purity, hostile input
def test_output_is_independent_of_row_and_fix_order():
    rows, fixes, kev = many_rows(40, 10, 10)
    a = run(rows, fixes, kev, kernel=kern_ok()).to_data()
    rnd = random.Random(5)
    r2, f2 = rows[:], fixes[:]
    rnd.shuffle(r2)
    rnd.shuffle(f2)
    b = run(r2, f2, kev, kernel=kern_ok()).to_data()
    assert json.dumps(a, sort_keys=False) == json.dumps(b, sort_keys=False)


def test_inputs_are_not_mutated_and_repeat_runs_are_byte_identical():
    rows = copy.deepcopy([GLIBC_OLD] + KROWS)
    snap_rows = copy.deepcopy(rows)
    kv = dict(KEV)
    a = run(rows, DEB_FIXES, kv, kernel=kern_ok("linux-image-6.1.0-17-amd64", "6.1.69-1", "x")).to_data()
    b = run(rows, DEB_FIXES, kv, kernel=kern_ok("linux-image-6.1.0-17-amd64", "6.1.69-1", "x")).to_data()
    assert rows == snap_rows and kv == KEV
    assert json.dumps(a) == json.dumps(b)


def test_output_does_not_depend_on_the_hash_seed():
    prog = (
        "import sys, json; sys.path.insert(0, %r); sys.path.insert(0, %r)\n"
        "import tests.test_vulnmatch as T\n"
        "rows, fixes, kev = T.many_rows(30, 8, 8)\n"
        "print(json.dumps(T.run(rows + T.KROWS, fixes, kev, kernel=T.kern_ok()).to_data()))\n"
    ) % (str(pathlib.Path(__file__).parent.parent), str(pathlib.Path(__file__).parent.parent.parent))
    outs = set()
    for seed in ("0", "1", "4242"):
        p = subprocess.run([sys.executable, "-I", "-c", prog], capture_output=True, text=True,
                           env={"PYTHONHASHSEED": seed, "PATH": "/usr/bin:/bin"}, cwd=str(pathlib.Path(__file__).parent.parent))
        assert p.returncode == 0, p.stderr[-800:]
        outs.add(p.stdout)
    assert len(outs) == 1


def test_naive_datetimes_are_refused_everywhere():
    naive = dt.datetime(2026, 1, 1)
    with pytest.raises(ValueError):
        Fix(scope="debian:bookworm", cve="CVE-2023-4911", pkg="a", pkg_kind="source", state="fixed", fixed_evr="1-1",
            first_seen_at=naive)
    with pytest.raises(ValueError):
        KevEntry(cve="CVE-2023-4911", date_added=naive, first_seen_at=NOW)
    with pytest.raises(ValueError):
        run([GLIBC_OLD], DEB_FIXES, KEV, now=naive)


def test_model_validation_refuses_garbage_enums_and_ids():
    with pytest.raises(ValueError):
        Fix(scope="debian:bookworm", cve="CVE-2023-4911", pkg="a", pkg_kind="source", state="maybe", fixed_evr="1-1", first_seen_at=NOW)
    with pytest.raises(ValueError):
        Fix(scope="debian:bookworm", cve="not-a-cve", pkg="a", pkg_kind="source", state="fixed", fixed_evr="1-1", first_seen_at=NOW)
    with pytest.raises(ValueError):
        Fix(scope="debian:bookworm", cve="CVE-2023-4911", pkg="a", pkg_kind="weird", state="fixed", fixed_evr="1-1", first_seen_at=NOW)
    with pytest.raises(ValueError):
        KevEntry(cve="CVE-2023-4911", date_added="2023-01-01", first_seen_at=NOW)
    with pytest.raises(ValueError):
        KernelInfo(state="maybe")
    with pytest.raises(ValueError):
        HostInput(os=DEB12, mgr="apk", rows=(), kernel=None, meta=None, containerised=False, manifest_sha=SHA, posture_manifest_sha=SHA)


def test_kev_entry_accepts_a_date_and_reads_it_as_midnight_utc():
    e = KevEntry(cve="CVE-2023-4911", date_added=dt.date(2023, 11, 21), first_seen_at=NOW, due_date=dt.date(2023, 12, 12))
    assert e.date_added == D(2023, 11, 21)


def test_hostile_version_strings_never_pass_for_patched():
    big = "2.36-9+deb12u" + "9" * 9000
    for v in ["v2.36-9+deb12u2", "２.36-9", "2.36-9+deb12u2\x00", "2.36-9;+deb12u2", "99999999999:2.36-9", "2.36-9+deb12u" + "9" * 300, big]:
        res = run([row("libc6", v, "glibc", v)], DEB_FIXES, KEV, kernel=kern_ok())
        assert res.open == () and unk_of(res) == {("CVE-2023-4911", "glibc"): "version_unparsable"}, v[:30]
        assert leaf(res).value is None


def test_epoch_and_tilde_tricks_get_the_real_dpkg_order():
    # an honest higher epoch really is newer; "~" really is older
    assert run([row("libc6", "1:1.0-1", "glibc", "1:1.0-1")], DEB_FIXES, KEV, kernel=kern_ok()).open == ()
    assert run([row("libc6", "2.36-9+deb12u3~rc1", "glibc", "2.36-9+deb12u3~rc1")], DEB_FIXES, KEV, kernel=kern_ok()).open != ()
    assert run([row("libc6", "0:2.36-9+deb12u2", "glibc", "0:2.36-9+deb12u2")], DEB_FIXES, KEV, kernel=kern_ok()).open != ()


def test_a_package_named_like_the_kernel_does_not_become_the_kernel():
    rows = [row("linux-image-evil", "9.9-9", "linux", "9.9-9")] + KROWS
    res = run(rows, KFIX, KEV, kernel=kern_ok("linux-image-6.1.0-17-amd64", "6.1.69-1", "6.1.0-17-amd64"))
    assert [(i.pkg, i.inst) for i in res.open] == [("linux", "6.1.69-1")]          # the collector's package decides


def test_performance_sanity_for_a_realistic_host():
    rnd = random.Random(1)
    rows = [row("pkg%d" % i, "1.%d-1" % i) for i in range(1800)]
    fixes, kev = [], {}
    for i in range(79):
        cve = "CVE-2023-%04d" % (1000 + i)
        kev[cve] = kevrow(cve, D(2023, 6, 1))
        fixes.append(fixrow(cve, "src%d" % i, "1.0-1", at=D(2023, 5, 1)))
        if i < 60:
            rows.append(row("src%d-bin" % i, "0.1-1", "src%d" % i, "0.1-1"))
    rnd.shuffle(rows)
    idx = FixIndex(fixes)
    h = host(rows, kernel=kern_ok())
    ev = evidence("debian:bookworm", kev)
    t = time.perf_counter()
    for _ in range(20):
        res = match_host(h, scopes=SCOPES, fixes=idx, kev=kev, evidence=ev, now=NOW)
    per = (time.perf_counter() - t) / 20
    assert len(res.open) == 60
    assert per < 0.25                                             # contract: about 0.5 ms; the bound only catches a blow-up


def test_fixindex_row_set_hash_is_stable_and_sensitive_to_relevant_rows_only():
    a = FixIndex(DEB_FIXES).row_set_hash("debian:bookworm")
    assert a == FixIndex(list(reversed(DEB_FIXES))).row_set_hash("debian:bookworm")
    assert re.fullmatch(r"[0-9a-f]{64}", a)
    changed = [dataclass_replace(f, fixed_evr="2.36-9+deb12u4") if f.pkg == "glibc" else f for f in DEB_FIXES]
    assert a != FixIndex(changed).row_set_hash("debian:bookworm")
    other_scope = DEB_FIXES + [fixrow("CVE-2023-4911", "glibc", "1-1", scope="debian:trixie")]
    assert a == FixIndex(other_scope).row_set_hash("debian:bookworm")
    # first_seen_at is evidence of the clock: it is part of the hash (a re-seen row must re-match)
    moved = [dataclass_replace(f, first_seen_at=f.first_seen_at + days(1)) for f in DEB_FIXES]
    assert a != FixIndex(moved).row_set_hash("debian:bookworm")
    names = FixIndex(DEB_FIXES).names("debian:bookworm")
    assert names == frozenset({"glibc", "linux", "openssh"})


def test_from_patch_reads_the_patch_fact_shape():
    data = {"os": {"state": "ok", "id": "debian", "id_like": [], "version_id": "12", "codename": "bookworm",
                   "pretty_name": "x", "family": "debian", "arch": "amd64"},
            "manifest": {"state": "ok", "mgr": "dpkg", "count": 1, "sha256": SHA, "held": 0, "full": True},
            "kernel": {"state": "ok", "running": "6.1.0-18-amd64", "package": "linux-image-6.1.0-18-amd64",
                       "package_version": "6.1.76-1", "livepatch": False}}
    h = HostInput.from_patch(data, rows=[GLIBC_OLD], stored_manifest_sha=SHA)
    assert h.os == DEB12 and h.mgr == "dpkg" and h.posture_manifest_sha == SHA and h.manifest_sha == SHA
    assert h.kernel == kern_ok()
    res = match_host(h, scopes=SCOPES, fixes=DEB_FIXES, kev=KEV, evidence=evidence("debian:bookworm", KEV), now=NOW)
    assert res.status == "ok" and len(res.open) == 1
    # a section that is not ok reads as nothing known
    bad = dict(data, os={"state": "unavailable", "reason": "no_data"}, kernel={"state": "unavailable", "reason": "unmanaged_kernel",
                                                                                 "running": "6.1.0-18-amd64", "livepatch": False})
    h2 = HostInput.from_patch(bad, rows=[GLIBC_OLD], stored_manifest_sha=SHA)
    assert h2.os.id is None and h2.kernel.state == "unavailable"
    assert match_host(h2, scopes=SCOPES, fixes=DEB_FIXES, kev=KEV, evidence=evidence("debian:bookworm", KEV), now=NOW).reason == "distro_unsupported"
    missing = HostInput.from_patch({"os": data["os"]}, rows=[GLIBC_OLD], stored_manifest_sha=SHA)
    assert missing.posture_manifest_sha is None
    res = match_host(missing, scopes=SCOPES, fixes=DEB_FIXES, kev=KEV, evidence=evidence("debian:bookworm", KEV), now=NOW)
    assert (res.status, res.reason) == ("error", "manifest_missing")


def test_golden_file_is_byte_stable():
    rows = load_dpkg_query()
    res = run(rows, DEB_FIXES, dict(KEV, **{"CVE-2024-6387": kevrow("CVE-2024-6387", D(2024, 7, 5))}),
              kernel=kern_ok("linux-image-6.1.0-17-amd64", "6.1.69-1", "6.1.0-17-amd64"))
    got = json.dumps(res.to_data(), indent=1, sort_keys=False) + "\n"
    golden = FIX / "golden_bookworm.json"
    assert golden.read_text() == got
