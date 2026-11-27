"""Scope resolution, identity cross-checks and the closed alias maps (contract 1.6.2, 1.6.4, 1.6.5).

Everything here is a *closed* list on purpose: a host's own strings (``ID``, codename, a package's
source name, ``ID_LIKE``) never extend what the code claims to judge. A name outside a map reads
"not mapped", and the caller turns that into UNKNOWN, never into "patched" or "not applicable".
"""
from __future__ import annotations

import datetime as dt
import re
from dataclasses import dataclass
from typing import Mapping, Optional

from .model import MANAGERS, Row, ScopeInfo

#: scope -> (family, vendor, release, version tag the release's packages carry)
SUPPORTED_RELEASES = {
    "debian:bookworm": ("deb", "debian", "bookworm", "12"),
    "debian:trixie": ("deb", "debian", "trixie", "13"),
    "ubuntu:jammy": ("deb", "ubuntu", "jammy", "22.04"),
    "ubuntu:noble": ("deb", "ubuntu", "noble", "24.04"),
    "rhel:8": ("rpm", "rhel", "8", "8"),
    "rhel:9": ("rpm", "rhel", "9", "9"),
    "alma:8": ("rpm", "alma", "8", "8"),
    "alma:9": ("rpm", "alma", "9", "9"),
}
#: os-release ``ID`` -> scope vendor. ``ID_LIKE`` is never consulted (a derivative's package set differs, D9).
OS_IDS = {"debian": "debian", "ubuntu": "ubuntu", "rhel": "rhel", "almalinux": "alma"}
_RPM_MAJOR = re.compile(r"([0-9]{1,2})(?:\.[0-9]{1,4})*\Z")

# ---------------------------------------------------------------------------------- notes
NOTE_ORDER = ("basis:distro_packages_only", "basis:installed_versions", "basis:advisory_feed_tls_only",
              "basis:no_fix_not_counted", "basis:package_origin_unverified",
              "basis:third_party_repositories_present", "basis:rhel_standard_stream_assumed")

#: apt ``Origin`` values that are the distribution itself, per scope vendor (closed; anything else is third party)
APT_ORIGINS = {"debian": frozenset({"Debian", "Debian Backports"}), "ubuntu": frozenset({"Ubuntu"})}


# -------------------------------------------------------------------------------- resolution
@dataclass(frozen=True)
class ScopeResolution:
    status: str                      # ok | unavailable
    scope: Optional[str]
    family: Optional[str]
    reason: str                      # distro_unsupported | release_eol | os_identity_inconsistent | ""
    info: Optional[ScopeInfo] = None
    vendor: str = ""
    tag: str = ""


def _no(reason: str, scope: Optional[str] = None, family: Optional[str] = None, info: Optional[ScopeInfo] = None,
        vendor: str = "", tag: str = "") -> ScopeResolution:
    return ScopeResolution("unavailable", scope, family, reason, info, vendor, tag)


def resolve_scope(os_, scopes: Mapping[str, ScopeInfo], now: dt.datetime) -> ScopeResolution:
    """Map the signed (untrusted) ``os`` block to one scope we claim to judge, or say why not."""
    ident = os_.id
    if type(ident) is not str or ident not in OS_IDS:
        return _no("distro_unsupported")
    vendor = OS_IDS[ident]
    if vendor in ("debian", "ubuntu"):
        if type(os_.codename) is not str:
            return _no("distro_unsupported")
        candidate = "%s:%s" % (vendor, os_.codename)
    else:
        m = _RPM_MAJOR.match(os_.version_id) if type(os_.version_id) is str else None
        if not m:
            return _no("distro_unsupported")
        candidate = "%s:%s" % (vendor, m.group(1))
    closed = SUPPORTED_RELEASES.get(candidate)
    info = scopes.get(candidate)
    if closed is None or info is None or info.family != closed[0]:
        return _no("distro_unsupported")
    family, _vendor, _release, tag = closed
    if family == "deb" and type(os_.version_id) is str and not (os_.version_id == tag or os_.version_id.startswith(tag + ".")):
        return _no("os_identity_inconsistent", candidate, family, info, vendor, tag)       # codename vs version_id
    if info.status == "eol":
        return _no("release_eol", candidate, family, info, vendor, tag)
    if info.status not in ("supported", "extended"):
        return _no("distro_unsupported")
    if info.support_until is not None and info.support_until <= now.date():
        return _no("release_eol", candidate, family, info, vendor, tag)
    return ScopeResolution("ok", candidate, family, "", info, vendor, tag)


# ------------------------------------------------------------------------ identity cross-check
_DEB_TAG = re.compile(r"[+~](?:deb|bpo)([0-9]+)")
_UBU_TAG = re.compile(r"(?:ubuntu[0-9]+\.|~)([0-9]{2}\.[0-9]{2})(?![0-9])")
_EL_TAG = re.compile(r"[.+]el([0-9]+)(?![0-9])")


def _tag_of(res: ScopeResolution, evr: str) -> Optional[str]:
    if res.vendor == "debian":
        m = _DEB_TAG.search(evr)
    elif res.vendor == "ubuntu":
        m = _UBU_TAG.search(evr)
    else:
        m = _EL_TAG.search(evr)
    return m.group(1) if m else None


def check_identity(res: ScopeResolution, mgr: Optional[str], rows: Optional[tuple]) -> str:
    """``""`` when the package list does not contradict the claimed release, else ``os_identity_inconsistent``.

    The manager must match the family, and more than half of the packages that carry a release tag must
    carry the claimed release's tag. (A fully lying signed host is out of scope: E2.)
    """
    if res.status != "ok" or mgr not in MANAGERS:
        return "os_identity_inconsistent"
    if (res.family == "deb") != (mgr == "dpkg"):
        return "os_identity_inconsistent"
    if not rows:
        return ""
    voters = hits = 0
    for r in rows:
        t = _tag_of(res, r.evr)
        if t is None:
            continue
        voters += 1
        if t == res.tag:
            hits += 1
    if voters and hits * 2 <= voters:
        return "os_identity_inconsistent"
    return ""


# ------------------------------------------------------------------------------ kernel aliases
#: Debian: the kernel source and its signed template; ``linux-latest`` is the meta source (never the running image)
DEBIAN_KERNEL_SOURCES = frozenset({"linux", "linux-signed-amd64", "linux-signed-arm64", "linux-signed-i386", "linux-latest"})

_UBU_FLAVOURS = ("aws|azure|gcp|gke|gkeop|ibm|oracle|kvm|lowlatency|raspi|oem|intel|nvidia-lowlatency|nvidia|riscv|"
                 "bluefield|fips|realtime|hwe")
_UBU_KERNEL = re.compile(
    r"linux(?:-(?:signed|meta|restricted-modules))?"
    r"(?:-(?P<flav>%s)(?P<ver>-[0-9]{1,2}\.[0-9]{1,2})?(?P<edge>-edge)?)?\Z" % _UBU_FLAVOURS)


def debian_kernel_key(src: str) -> Optional[str]:
    return "linux" if src in DEBIAN_KERNEL_SOURCES else None


def ubuntu_kernel_key(src: str) -> Optional[str]:
    """``linux-signed-aws`` -> ``linux-aws``; ``linux-signed`` -> ``linux``; anything off the closed list -> ``None``."""
    m = _UBU_KERNEL.match(src) if type(src) is str and src.startswith("linux") else None
    if not m:
        return None
    flav = m.group("flav")
    if not flav:
        return "linux"
    return "linux-%s%s%s" % (flav, m.group("ver") or "", m.group("edge") or "")


#: rpm kernel images (one of these owns the running kernel) and the kernel sub-packages that are not images
RPM_KERNEL_IMAGES = frozenset({"kernel", "kernel-core", "kernel-rt-core"})
RPM_KERNEL_OTHER = frozenset({
    "kernel-modules", "kernel-modules-core", "kernel-modules-extra", "kernel-devel", "kernel-headers", "kernel-doc",
    "kernel-tools", "kernel-tools-libs", "kernel-tools-libs-devel", "kernel-abi-stablelists", "kernel-uki-virt",
    "kernel-rt", "kernel-rt-modules", "kernel-rt-modules-core", "kernel-rt-modules-extra", "kernel-rt-devel",
    "kernel-debug", "kernel-debug-core", "kernel-debug-modules", "kernel-debug-modules-core",
    "kernel-debug-modules-extra", "kernel-debug-devel", "kernel-zfcpdump", "kernel-zfcpdump-core",
    "kernel-zfcpdump-modules", "kernel-zfcpdump-devel", "perf", "python3-perf", "bpftool", "libperf",
})


def kernel_key(res: ScopeResolution, row: Row) -> Optional[str]:
    """The kernel source key a row belongs to (the row is then judged only as the running image), else ``None``."""
    if res.family == "deb":
        return debian_kernel_key(row.src) if res.vendor == "debian" else ubuntu_kernel_key(row.src)
    return row.name if (row.name in RPM_KERNEL_IMAGES or row.name in RPM_KERNEL_OTHER) else None


def is_kernel_fix_key(res: ScopeResolution, key: str) -> bool:
    if res.family == "deb":
        return (key == "linux") if res.vendor == "debian" else ubuntu_kernel_key(key) == key
    return key in RPM_KERNEL_IMAGES


def is_kernel_image_row(res: ScopeResolution, row: Row) -> bool:
    """Could this row be the package that owns the running kernel?"""
    if kernel_key(res, row) is None:
        return False
    if res.family == "deb":
        return row.name.startswith("linux-image-")
    return row.name in RPM_KERNEL_IMAGES


def junk_rpm_row(row: Row) -> bool:
    """Rows an rpm list never judges: source rpms, debug packages, imported keys."""
    return (row.arch in ("src", "nosrc") or row.name in ("gpg-pubkey",)
            or row.name.endswith("-debuginfo") or row.name.endswith("-debugsource"))


# ----------------------------------------------------------------------------- apt origins
def third_party_from_origins(vendor: str, origins: tuple) -> bool:
    """True when any ``apt-cache policy`` summary entry is not the distribution's own origin (or is unreadable)."""
    allowed = APT_ORIGINS.get(vendor, frozenset())
    for entry in origins:
        origin = None
        if type(entry) is str:
            for tok in entry.split(","):
                k, eq, v = tok.partition("=")
                if eq and k == "o":
                    origin = v
                    break
        if origin is None or origin not in allowed:
            return True
    return False
