"""Plain, validated data for the matcher (contract 1.6). No I/O, no clock.

Every datetime is timezone-aware and floored to whole seconds in UTC; a naive datetime is refused
(an ambiguous instant is a wrong exposure clock). Validation failures raise :class:`ModelError` (a
``ValueError``); the one deliberately soft entry point is :func:`parse_rows`, which returns ``None``
for a malformed package list so the caller reads UNKNOWN ``manifest_missing`` instead of crashing.
"""
from __future__ import annotations

import datetime as dt
import hashlib
import re
from dataclasses import dataclass
from typing import Any, Iterable, Mapping, NamedTuple, Optional

UTC = dt.timezone.utc

FIX_STATES = ("fixed", "open", "not_affected", "undetermined", "esm_only")
PKG_KINDS = ("source", "binary")
FAMILIES = ("deb", "rpm")
MANAGERS = ("dpkg", "rpm")
CVE_RE = re.compile(r"CVE-[0-9]{4}-[0-9]{4,10}\Z")
SHA256_RE = re.compile(r"[0-9a-f]{64}\Z")

MAX_ROWS = 20000                 # the server caps a list at 8000; a larger one is not a package list
MAX_FIELD = 512
MAX_NAME = 200

#: reasons an individual ``(cve, package)`` can be UNKNOWN (``unknown[].reason`` in the fact data)
ITEM_REASONS = ("kernel_unknown", "livepatch", "esm_package", "foreign_signature", "modular_package",
                "version_unparsable", "esm_only_fix", "undetermined")


class ModelError(ValueError):
    pass


def utc(v: Any, what: str) -> dt.datetime:
    """An aware datetime in UTC, floored to the second."""
    if not isinstance(v, dt.datetime) or v.tzinfo is None or v.utcoffset() is None:
        raise ModelError("%s must be a timezone-aware datetime" % what)
    return v.astimezone(UTC).replace(microsecond=0)


def _opt_utc(v: Any, what: str) -> Optional[dt.datetime]:
    return None if v is None else utc(v, what)


def _day(v: Any, what: str) -> dt.datetime:
    """A day-only source date is read as 00:00:00Z of that day, the earliest instant (D5)."""
    if isinstance(v, dt.datetime):
        return utc(v, what)
    if isinstance(v, dt.date):
        return dt.datetime(v.year, v.month, v.day, tzinfo=UTC)
    raise ModelError("%s must be a date or an aware datetime" % what)


def _str(v: Any, what: str, *, max_len: int = MAX_FIELD, allow_empty: bool = True) -> str:
    if type(v) is not str or len(v) > max_len or (not allow_empty and not v):
        raise ModelError("%s must be a string of at most %d characters" % (what, max_len))
    return v


def _opt_str(v: Any, what: str) -> Optional[str]:
    return None if v is None else _str(v, what)


def _set(obj: Any, name: str, value: Any) -> None:
    object.__setattr__(obj, name, value)


def kev_ids_sha(ids: Iterable[str]) -> str:
    """sha256 of the sorted, de-duplicated KEV id set joined by newlines (D7).

    The advisory snapshot records the sha of the set it was filtered with; the matcher requires it to
    equal the current KEV set, so a freshly listed CVE can never read "patched" because its rows were
    filtered out by an older set. A mapping is its key set.
    """
    return hashlib.sha256("\n".join(sorted(set(ids))).encode("ascii", "replace")).hexdigest()


# ------------------------------------------------------------------------------- advisory data
@dataclass(frozen=True)
class Fix:
    """One advisory statement for ``(scope, cve, pkg)``; mirrors a row of ``advisory_fixes``."""
    scope: str
    cve: str
    pkg: str
    pkg_kind: str
    state: str
    first_seen_at: dt.datetime            # our first sighting of this row: the upper bound of its date (D5, D6)
    fixed_evr: str = ""
    advisory_id: str = ""
    fixed_at: Optional[dt.datetime] = None      # the advisory's publication; None = undated
    urgency: str = ""
    stream: str = ""
    modular: bool = False
    removed: bool = False                 # removed_at IS NOT NULL: the index skips it

    def __post_init__(self) -> None:
        _str(self.scope, "scope", max_len=64, allow_empty=False)
        if type(self.cve) is not str or not CVE_RE.match(self.cve):
            raise ModelError("bad CVE id")
        _str(self.pkg, "pkg", max_len=MAX_NAME, allow_empty=False)
        if self.pkg_kind not in PKG_KINDS:
            raise ModelError("bad pkg_kind")
        if self.state not in FIX_STATES:
            raise ModelError("bad state")
        _str(self.fixed_evr, "fixed_evr")
        _str(self.advisory_id, "advisory_id", max_len=128)
        _str(self.urgency, "urgency", max_len=64)
        _str(self.stream, "stream", max_len=128)
        if type(self.modular) is not bool or type(self.removed) is not bool:
            raise ModelError("modular/removed must be bool")
        _set(self, "first_seen_at", utc(self.first_seen_at, "first_seen_at"))
        _set(self, "fixed_at", _opt_utc(self.fixed_at, "fixed_at"))


@dataclass(frozen=True)
class KevEntry:
    """One CISA KEV entry; mirrors a row of ``kev_entries``."""
    cve: str
    date_added: dt.datetime               # a DATE is read as 00:00:00Z
    first_seen_at: dt.datetime
    due_date: Optional[dt.date] = None    # shown, never the clock (D5)
    ransomware: bool = False

    def __post_init__(self) -> None:
        if type(self.cve) is not str or not CVE_RE.match(self.cve):
            raise ModelError("bad CVE id")
        _set(self, "date_added", _day(self.date_added, "date_added"))
        _set(self, "first_seen_at", utc(self.first_seen_at, "first_seen_at"))
        if self.due_date is not None and (not isinstance(self.due_date, dt.date) or isinstance(self.due_date, dt.datetime)):
            raise ModelError("due_date must be a date")
        if type(self.ransomware) is not bool:
            raise ModelError("ransomware must be bool")


@dataclass(frozen=True)
class ScopeInfo:
    """One row of ``advisory_scopes``."""
    scope: str
    family: str
    vendor: str
    release: str
    status: str
    support_until: Optional[dt.date] = None
    dating_sources: tuple = ()
    max_staleness_s: int = 172800
    key_ids: tuple = ()

    def __post_init__(self) -> None:
        _str(self.scope, "scope", max_len=64, allow_empty=False)
        if self.family not in FAMILIES:
            raise ModelError("bad family")
        _str(self.vendor, "vendor", max_len=64)
        _str(self.release, "release", max_len=64)
        _str(self.status, "status", max_len=32)          # an unknown status is judged by the resolver, never "supported"
        if self.support_until is not None and (not isinstance(self.support_until, dt.date) or isinstance(self.support_until, dt.datetime)):
            raise ModelError("support_until must be a date")
        _set(self, "dating_sources", tuple(self.dating_sources))
        _set(self, "key_ids", tuple(self.key_ids))
        if type(self.max_staleness_s) is not int or self.max_staleness_s <= 0:
            raise ModelError("max_staleness_s must be a positive int")


@dataclass(frozen=True)
class SnapshotRef:
    """A current advisory snapshot (``advisory_snapshots``)."""
    source: str
    scope: str
    id: int
    sha256: str
    fetched_at: dt.datetime
    kev_ids_sha: str = ""

    def __post_init__(self) -> None:
        _str(self.source, "source", max_len=64, allow_empty=False)
        _str(self.scope, "scope", max_len=64)
        if type(self.id) is not int:
            raise ModelError("id must be int")
        if type(self.sha256) is not str or not SHA256_RE.match(self.sha256):
            raise ModelError("sha256 must be 64 hex")
        _str(self.kev_ids_sha, "kev_ids_sha", max_len=64)
        _set(self, "fetched_at", utc(self.fetched_at, "fetched_at"))


@dataclass(frozen=True)
class KevSnapshot:
    """The current KEV catalogue snapshot."""
    id: int
    sha256: str
    fetched_at: dt.datetime
    catalog_version: str
    ids_sha: str                          # kev_ids_sha(the KEV id set the matcher is given)

    def __post_init__(self) -> None:
        if type(self.id) is not int:
            raise ModelError("id must be int")
        if type(self.sha256) is not str or not SHA256_RE.match(self.sha256):
            raise ModelError("sha256 must be 64 hex")
        _str(self.catalog_version, "catalog_version", max_len=64)
        _str(self.ids_sha, "ids_sha", max_len=64)
        _set(self, "fetched_at", utc(self.fetched_at, "fetched_at"))


@dataclass(frozen=True)
class Evidence:
    primary: Optional[SnapshotRef]
    dating: tuple = ()
    kev: Optional[KevSnapshot] = None

    def __post_init__(self) -> None:
        _set(self, "dating", tuple(self.dating))


# ---------------------------------------------------------------------------------- the host
class Row(NamedTuple):
    """``[name, evr, arch, src, srcevr]``: the package-list row the agent signs."""
    name: str
    evr: str
    arch: str
    src: str
    srcevr: str


def parse_rows(raw: Any) -> Optional[tuple]:
    """A package list as a sorted tuple of :class:`Row`, or ``None`` when it is not a package list."""
    if not isinstance(raw, (list, tuple)) or len(raw) > MAX_ROWS:
        return None
    out = []
    for r in raw:
        if not isinstance(r, (list, tuple)) or len(r) != 5:
            return None
        for x in r:
            if type(x) is not str or len(x) > MAX_FIELD:
                return None
        if not (r[0] and r[3]):
            return None                                         # a row without a name or a source name cannot be looked up
        out.append(Row(*r))
    return tuple(sorted(out))


@dataclass(frozen=True)
class OsInfo:
    """The (signed, untrusted) ``patch.os`` block."""
    id: Optional[str] = None
    version_id: Optional[str] = None
    codename: Optional[str] = None

    def __post_init__(self) -> None:
        _opt_str(self.id, "id")
        _opt_str(self.version_id, "version_id")
        _opt_str(self.codename, "codename")


@dataclass(frozen=True)
class KernelInfo:
    """The ``patch.kernel`` block: ``ok`` (the running kernel's owning package) or ``unavailable``."""
    state: str
    reason: str = ""
    running: Optional[str] = None
    package: Optional[str] = None
    package_version: Optional[str] = None
    livepatch: Optional[bool] = None

    def __post_init__(self) -> None:
        if self.state not in ("ok", "unavailable"):
            raise ModelError("bad kernel state")
        _str(self.reason, "reason", max_len=64)
        _opt_str(self.running, "running")
        _opt_str(self.package, "package")
        _opt_str(self.package_version, "package_version")
        if self.livepatch is not None and type(self.livepatch) is not bool:
            raise ModelError("livepatch must be bool or None")


@dataclass(frozen=True)
class HostMeta:
    """``patch.manifest.meta`` (agent patch collector v2); ``None`` on the host means an older agent."""
    foreign: frozenset = frozenset()
    modular: frozenset = frozenset()
    apt_origins: Optional[tuple] = None

    def __post_init__(self) -> None:
        _set(self, "foreign", frozenset(self.foreign))
        _set(self, "modular", frozenset(self.modular))
        if self.apt_origins is not None:
            _set(self, "apt_origins", tuple(self.apt_origins))


def _blk(data: Any, name: str) -> Optional[Mapping[str, Any]]:
    b = data.get(name) if isinstance(data, Mapping) else None
    return b if isinstance(b, Mapping) else None


def _s(m: Mapping[str, Any], key: str) -> Optional[str]:
    v = m.get(key)
    return v if type(v) is str and len(v) <= MAX_FIELD else None


@dataclass(frozen=True)
class HostInput:
    os: OsInfo
    mgr: Optional[str]
    rows: Optional[tuple]
    kernel: Optional[KernelInfo]
    meta: Optional[HostMeta]
    containerised: bool
    manifest_sha: str                              # the stored list's digest (``agent_manifest_refs.manifest_sha``)
    posture_manifest_sha: Optional[str]            # the newest verified posture's digest (the ``patch`` fact)

    def __post_init__(self) -> None:
        if self.mgr is not None and self.mgr not in MANAGERS:
            raise ModelError("bad package manager")
        if self.rows is not None and (not isinstance(self.rows, tuple) or not all(isinstance(r, Row) for r in self.rows)):
            raise ModelError("rows must come from parse_rows")
        if type(self.containerised) is not bool:
            raise ModelError("containerised must be bool")
        _str(self.manifest_sha, "manifest_sha", max_len=64)
        _opt_str(self.posture_manifest_sha, "posture_manifest_sha")

    @classmethod
    def from_patch(cls, data: Any, *, rows: Any, stored_manifest_sha: str, meta: Optional[HostMeta] = None,
                   containerised: bool = False) -> "HostInput":
        """Read the ``patch`` fact ``data`` (``os``, ``manifest``, ``kernel`` sub-blocks); a block that is
        not ``ok`` contributes nothing, so the matcher reads it as unknown."""
        osb = _blk(data, "os")
        os_ = OsInfo(_s(osb, "id"), _s(osb, "version_id"), _s(osb, "codename")) if osb and osb.get("state") == "ok" else OsInfo()
        mb = _blk(data, "manifest")
        mgr = posture = None
        if mb and mb.get("state") == "ok":
            mgr = mb.get("mgr") if mb.get("mgr") in MANAGERS else None
            sha = _s(mb, "sha256")
            posture = sha if sha and SHA256_RE.match(sha) else None
        kb = _blk(data, "kernel")
        kernel = None
        if kb and kb.get("state") == "ok":
            lp = kb.get("livepatch")
            kernel = KernelInfo("ok", running=_s(kb, "running"), package=_s(kb, "package"),
                                package_version=_s(kb, "package_version"), livepatch=lp if type(lp) is bool else None)
        elif kb and kb.get("state") == "unavailable":
            lp = kb.get("livepatch")
            kernel = KernelInfo("unavailable", reason=_s(kb, "reason") or "", running=_s(kb, "running"),
                                livepatch=lp if type(lp) is bool else None)
        return cls(os=os_, mgr=mgr, rows=parse_rows(rows), kernel=kernel, meta=meta, containerised=containerised,
                   manifest_sha=stored_manifest_sha, posture_manifest_sha=posture)
