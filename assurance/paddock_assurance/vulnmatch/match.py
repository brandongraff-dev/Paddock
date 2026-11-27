"""``match_host``: one host's package list against one scope's KEV advisory rows (contract 1.6.3 to 1.6.6).

Pure and deterministic: no I/O, no clock but the ``now`` argument, no iteration over unordered
containers without sorting. The result carries everything the ``kev`` fact needs; the N-day decision
itself is *not* made here (N is a parameter of the invariant): :mod:`.leaf` takes ``MatchResult.to_data()``
and ``now``. Soundness rules enforced here, each pinned by a test:

* an installed row is compared only when its package is KEV-relevant for the scope; nothing it says can
  turn an irrelevant package into UNKNOWN, and nothing can turn a relevant one into "patched" except a
  successful ``installed >= fixed`` comparison;
* a statement the code cannot compare (ESM tag, modular, foreign signature, unparsable text, undetermined,
  ESM-only) is UNKNOWN with its reason; a provable violation on the same host still wins in the leaf;
* only the RUNNING kernel image is judged, by its binary version, through closed alias maps; a kernel that
  is unknown, unmapped, not an installed row or livepatched makes every kernel item UNKNOWN;
* a fix or KEV date later than our own first sighting is clamped to it and is then only an upper bound
  (``basis: first_seen``): it can prove a violation, never a pass.
"""
from __future__ import annotations

import dataclasses
import datetime as dt
import hashlib
from collections import defaultdict
from typing import Any, Iterable, Mapping, Optional

from . import scopes as S
from .model import (ITEM_REASONS, Evidence, Fix, HostInput, KevEntry, ModelError, Row, ScopeInfo, SnapshotRef,
                    kev_ids_sha, utc)
from .vercmp import VersionError, cmp_for, is_esm_version, is_modular_evr

DEFAULT_MAX_AGE = dt.timedelta(hours=48)
CAP_OPEN = 100
CAP_UNKNOWN = 50
CAP_NO_FIX = 50
_RANK = {r: i for i, r in enumerate(ITEM_REASONS)}


# ----------------------------------------------------------------------------------- index
def _fix_sort(f: Fix) -> tuple:
    return (f.cve, f.state, f.fixed_evr, f.advisory_id, f.stream, f.modular, f.first_seen_at,
            f.fixed_at or dt.datetime.min.replace(tzinfo=dt.timezone.utc))


class FixIndex:
    """Advisory rows indexed by scope, kind and package name, grouped by CVE. Removed rows are dropped."""

    def __init__(self, fixes: Iterable[Fix]):
        raw: dict = defaultdict(lambda: {"source": defaultdict(list), "binary": defaultdict(list)})
        for f in fixes:
            if not isinstance(f, Fix):
                raise ModelError("fixes must be Fix rows")
            if f.removed:
                continue
            raw[f.scope][f.pkg_kind][f.pkg].append(f)
        self._rows: dict = {}
        self._groups: dict = {}
        for scope, kinds in raw.items():
            rows: dict = {}
            groups: dict = {}
            for kind, pk in kinds.items():
                rows[kind] = {k: tuple(sorted(v, key=_fix_sort)) for k, v in pk.items()}
                g = {}
                for k, v in rows[kind].items():
                    per: dict = defaultdict(list)
                    for f in v:
                        per[f.cve].append(f)
                    g[k] = tuple((cve, tuple(fs)) for cve, fs in sorted(per.items()))
                groups[kind] = g
            self._rows[scope] = rows
            self._groups[scope] = groups

    def groups(self, scope: str, kind: str) -> Mapping[str, tuple]:
        """``{package: ((cve, (Fix, ...)), ...)}`` for one scope and kind."""
        return self._groups.get(scope, {}).get(kind, {})

    def names(self, scope: str) -> frozenset:
        """Every package name that has at least one advisory row in the scope (the 'relevant names')."""
        rows = self._rows.get(scope, {})
        return frozenset(k for kind in rows.values() for k in kind)

    def row_set_hash(self, scope: str) -> str:
        """A digest of the scope's rows (everything that can change a match, including first sightings).

        The builder's input key uses it instead of a snapshot id: a refresh that changes nothing relevant
        changes nothing here (contract 1.10 b).
        """
        h = hashlib.sha256()
        lines = []
        for kind, pk in self._rows.get(scope, {}).items():
            for name, fs in pk.items():
                for f in fs:
                    lines.append("\x1f".join((kind, name, f.cve, f.state, f.fixed_evr, f.advisory_id, f.stream,
                                              "1" if f.modular else "0", f.fixed_at.isoformat() if f.fixed_at else "",
                                              f.first_seen_at.isoformat())))
        for line in sorted(lines):
            h.update(line.encode("utf-8", "replace"))
            h.update(b"\n")
        return h.hexdigest()


# ----------------------------------------------------------------------------------- result
@dataclasses.dataclass(frozen=True)
class OpenItem:
    cve: str
    pkg: str
    inst: str
    fixed: str
    adv: str
    fix_at: dt.datetime
    basis: str                      # advisory | first_seen: how certain ``clock_start`` is
    kev_at: dt.datetime
    due: Optional[str]
    ransom: bool

    @property
    def clock_start(self) -> dt.datetime:
        return max(self.fix_at, self.kev_at)


@dataclasses.dataclass(frozen=True)
class UnknownItem:
    cve: str
    pkg: str
    reason: str


@dataclasses.dataclass(frozen=True)
class NoFixItem:
    cve: str
    pkg: str


def _z(t: dt.datetime) -> str:
    return t.strftime("%Y-%m-%dT%H:%M:%SZ")


def _sha12(s: str) -> str:
    return s[:12]


@dataclasses.dataclass(frozen=True)
class MatchResult:
    status: str                                   # ok | unavailable | error
    reason: str = ""
    scope: str = ""
    open: tuple = ()
    unknown: tuple = ()
    no_fix: tuple = ()
    relevant: int = 0
    third_party_sources: Optional[bool] = None
    notes: tuple = ()
    exact: bool = False                           # False when a kernel item is blind (livepatch / kernel unknown)
    manifest_sha: str = ""
    manifest_count: int = 0
    primary: Optional[SnapshotRef] = None
    dating: tuple = ()
    kev_snapshot: Any = None
    valid_until: Optional[dt.datetime] = None

    @property
    def fetched_min(self) -> Optional[dt.datetime]:
        """The older of the primary and KEV fetch times: the ``observed_at`` cap of the fact (contract 1.7)."""
        if self.primary is None or self.kev_snapshot is None:
            return None
        return min(self.primary.fetched_at, self.kev_snapshot.fetched_at)

    def evidence_tail(self) -> str:
        """``kev:<manifest12>|adv:<snapshot ids>:<sha12>|kev:<id>:<sha12>`` (the tail of the fact's ``evidence_ref``)."""
        if self.status != "ok" or self.primary is None or self.kev_snapshot is None:
            return ""
        ids = [str(self.primary.id)] + [str(d.id) for d in sorted(self.dating, key=lambda d: d.source)]
        return "kev:%s|adv:%s:%s|kev:%d:%s" % (_sha12(self.manifest_sha), "+".join(ids), _sha12(self.primary.sha256),
                                                self.kev_snapshot.id, _sha12(self.kev_snapshot.sha256))

    def to_data(self) -> dict:
        """The ``data`` of the ``kev`` fact (contract 1.7): sorted, capped, no floats, byte-stable."""
        if self.status != "ok":
            return {"v": 1, "scope": self.scope, "reason": self.reason}
        opens = sorted(self.open, key=lambda i: (i.clock_start, i.cve, i.pkg))
        unknown = sorted(self.unknown, key=lambda i: (i.cve, i.pkg, i.reason))
        no_fix = sorted(self.no_fix, key=lambda i: (i.cve, i.pkg))
        reasons: dict = defaultdict(int)
        for u in unknown:
            reasons[u.reason] += 1
        assert self.primary is not None and self.kev_snapshot is not None and self.valid_until is not None
        return {
            "v": 1,
            "scope": self.scope,
            "manifest": {"sha256": self.manifest_sha, "count": self.manifest_count},
            "snap": {
                "primary": {"id": self.primary.id, "sha12": _sha12(self.primary.sha256), "fetched_at": _z(self.primary.fetched_at)},
                "dating": [{"source": d.source, "id": d.id, "sha12": _sha12(d.sha256), "fetched_at": _z(d.fetched_at)}
                           for d in sorted(self.dating, key=lambda d: (d.source, d.id))],
                "kev": {"id": self.kev_snapshot.id, "sha12": _sha12(self.kev_snapshot.sha256),
                        "catalog": self.kev_snapshot.catalog_version, "fetched_at": _z(self.kev_snapshot.fetched_at)},
                "valid_until": _z(self.valid_until),
            },
            "counts": {"relevant": self.relevant, "open_fix": len(opens), "no_fix": len(no_fix), "undecided": len(unknown)},
            "open": [{"cve": i.cve, "pkg": i.pkg, "inst": i.inst, "fixed": i.fixed, "adv": i.adv, "fix_at": _z(i.fix_at),
                      "basis": i.basis, "kev_at": _z(i.kev_at), "due": i.due, "ransom": i.ransom} for i in opens[:CAP_OPEN]],
            "open_truncated": len(opens) > CAP_OPEN,
            "unknown": [{"cve": u.cve, "pkg": u.pkg, "reason": u.reason} for u in unknown[:CAP_UNKNOWN]],
            "unknown_total": len(unknown),
            "unknown_reasons": {k: reasons[k] for k in sorted(reasons)},
            "no_fix": [{"cve": n.cve, "pkg": n.pkg} for n in no_fix[:CAP_NO_FIX]],
            "no_fix_total": len(no_fix),
            "third_party_sources": self.third_party_sources,
            "notes": list(self.notes),
        }


def _fail(status: str, reason: str, scope: Optional[str] = None) -> MatchResult:
    return MatchResult(status=status, reason=reason, scope=scope or "")


# ------------------------------------------------------------------------------ the decision
def _eff_fix_date(f: Fix, dating_ok: bool) -> tuple:
    """``(date, basis)``: a dated advisory is certain; an undated, demoted or future-dated one is an upper bound."""
    if f.fixed_at is not None and dating_ok and f.fixed_at <= f.first_seen_at:
        return f.fixed_at, "advisory"
    return f.first_seen_at, "first_seen"


def _open_item(label: str, inst: str, unmet: list, k: KevEntry, dating_ok: bool) -> tuple:
    effs = [(_eff_fix_date(f, dating_ok), f) for f in unmet]
    (f_date, _b), f0 = min(effs, key=lambda e: (e[0][0], e[1].advisory_id, e[1].fixed_evr))
    f_basis = "advisory" if all(b == "advisory" for (_d, b), _f in effs) else "first_seen"
    k_date = min(k.date_added, k.first_seen_at)
    k_basis = "advisory" if k.date_added <= k.first_seen_at else "first_seen"
    # the binding component of max(fix, kev) decides how certain the clock is; a tie is certain if either side is
    if f_date > k_date:
        basis = f_basis
    elif k_date > f_date:
        basis = k_basis
    else:
        basis = "advisory" if "advisory" in (f_basis, k_basis) else "first_seen"
    item = OpenItem(cve=k.cve, pkg=label, inst=inst, fixed=f0.fixed_evr, adv=f0.advisory_id, fix_at=f_date, basis=basis,
                    kev_at=k_date, due=k.due_date.isoformat() if k.due_date else None, ransom=k.ransomware)
    return (0, item.clock_start, inst, f0.fixed_evr), "open", item


def _decide(label: str, cve: str, stmts: tuple, inst: str, cmp: Any, ctx: Optional[str], k: KevEntry,
            dating_ok: bool) -> Optional[tuple]:
    """One ``(cve, package)``: ``(sortkey, kind, payload)`` or ``None`` when patched or not affected."""
    active = [s for s in stmts if s.state != "not_affected"]
    if not active:
        return None
    if ctx:
        return (1, _RANK[ctx], inst), "unknown", UnknownItem(cve, label, ctx)
    unmet = []
    reasons = set()
    nofix = False
    for s in active:
        if s.state == "open":
            nofix = True
        elif s.state == "undetermined":
            reasons.add("undetermined")
        elif s.state == "esm_only":
            reasons.add("esm_only_fix")
        elif s.modular:
            reasons.add("modular_package")
        elif not s.fixed_evr:
            reasons.add("undetermined")                       # resolved with no fixed version
        else:
            try:
                c = cmp(inst, s.fixed_evr)
            except VersionError:
                reasons.add("version_unparsable")
                continue
            if c < 0:
                unmet.append(s)
    if unmet:
        return _open_item(label, inst, unmet, k, dating_ok)    # a violation beats every unknown statement
    if reasons:
        r = min(reasons, key=_RANK.__getitem__)
        return (1, _RANK[r], inst), "unknown", UnknownItem(cve, label, r)
    if nofix:
        return (2,), "nofix", NoFixItem(cve, label)
    return None


def _running_kernel(res: S.ScopeResolution, host: HostInput, rows: tuple) -> tuple:
    """``(owner_row | None, kernel_key | None, reason)``; ``reason`` is ``""`` when the kernel is judgeable."""
    k = host.kernel
    if k is None or k.state != "ok" or k.livepatch is None or not k.package or not k.package_version:
        return None, None, "kernel_unknown"
    owner = next((r for r in rows if r.name == k.package and r.evr == k.package_version), None)
    if owner is None or not S.is_kernel_image_row(res, owner):
        return None, None, "kernel_unknown"                   # hidden, unmapped or not an installed image
    key = S.kernel_key(res, owner)
    if key is None:
        return None, None, "kernel_unknown"
    return owner, key, ("livepatch" if k.livepatch else "")


def match_host(host: HostInput, *, scopes: Mapping[str, ScopeInfo], fixes: Any, kev: Mapping[str, KevEntry],
               evidence: Evidence, now: dt.datetime, max_age: dt.timedelta = DEFAULT_MAX_AGE,
               kev_set_verified: bool = False) -> MatchResult:
    """Match ``host`` against the KEV rows of its scope.

    ``fixes``: a :class:`FixIndex` or any iterable of :class:`Fix` (rows of other scopes are ignored);
    ``kev``: the CURRENT KEV set by CVE id; ``evidence``: the snapshots those rows and that set came from;
    ``max_age``: the advisory staleness setting (the effective limit is the stricter of it and the scope's
    own ``max_staleness_s``). ``kev_set_verified=True`` skips re-hashing ``kev`` against the KEV snapshot
    (only for a caller that has already proved they are the same set).
    """
    now = utc(now, "now")
    if host.containerised:
        return _fail("unavailable", "containerised_agent")
    res = S.resolve_scope(host.os, scopes, now)
    if res.status != "ok" or res.info is None or res.scope is None or res.family is None:
        return _fail("unavailable", res.reason, res.scope)
    scope = res.scope
    if host.rows is None or host.mgr is None or not host.manifest_sha or host.posture_manifest_sha is None:
        return _fail("error", "manifest_missing", scope)
    if not host.rows or not all(r.name and r.src for r in host.rows):
        # a zero-package list is not evidence, and a row without a name or a source name cannot be looked up at
        # all (the agent always fills src): neither may read as "nothing found". An empty VERSION is different:
        # the row is still looked up and reads version_unparsable (UNKNOWN) when its package is KEV-relevant.
        return _fail("error", "manifest_missing", scope)
    if host.posture_manifest_sha != host.manifest_sha:
        return _fail("error", "manifest_not_current", scope)
    if S.check_identity(res, host.mgr, host.rows):
        return _fail("unavailable", "os_identity_inconsistent", scope)

    # ---- freshness: the stricter of the scope's limit and the setting; a fetch "in the future" counts as now
    limit = min(dt.timedelta(seconds=res.info.max_staleness_s), max_age)
    prim, ksnap = evidence.primary, evidence.kev
    if prim is None or ksnap is None or prim.scope != scope:
        return _fail("error", "advisory_stale", scope)

    def fresh(t: dt.datetime) -> bool:
        return now - min(t, now) <= limit

    if not fresh(prim.fetched_at) or not fresh(ksnap.fetched_at):
        return _fail("error", "advisory_stale", scope)
    if not prim.kev_ids_sha or prim.kev_ids_sha != ksnap.ids_sha:
        return _fail("error", "advisory_behind_kev", scope)
    if not kev or (not kev_set_verified and kev_ids_sha(kev) != ksnap.ids_sha):
        return _fail("error", "advisory_behind_kev", scope)           # an empty catalog is an anomaly, never "nothing exploited"
    have = {d.source: d for d in evidence.dating if d.scope == scope}
    dating_ok = all(s in have and fresh(have[s].fetched_at) for s in res.info.dating_sources)
    stamps = [min(prim.fetched_at, now), min(ksnap.fetched_at, now)] + [min(d.fetched_at, now) for d in have.values()]
    valid_until = min(stamps) + limit

    idx = fixes if isinstance(fixes, FixIndex) else FixIndex(fixes)
    if not idx.names(scope):
        return _fail("error", "advisory_stale", scope)                  # a current snapshot with no rows for the scope: anomaly
    src_groups = idx.groups(scope, "source")
    bin_groups = idx.groups(scope, "binary")
    base_cmp = cmp_for(res.family)
    cmp_memo: dict = {}

    def cmp(a: str, b: str) -> int:                           # one comparison per distinct pair per host
        key = (a, b)
        hit = cmp_memo.get(key)
        if hit is None:
            try:
                hit = base_cmp(a, b)
            except VersionError as e:
                hit = e
            cmp_memo[key] = hit
        if isinstance(hit, VersionError):
            raise hit
        return hit

    rows = host.rows
    if res.family == "rpm":
        rows = tuple(r for r in rows if not S.junk_rpm_row(r))
    meta = host.meta

    owner, okey, kreason = _running_kernel(res, host, rows)
    kernel_groups = src_groups if res.family == "deb" else bin_groups
    kernel_fix_keys = sorted(k for k in kernel_groups if S.is_kernel_fix_key(res, k))

    best: dict = {}
    relevant: set = set()
    done: set = set()

    def take(label: str, cve: str, got: Optional[tuple]) -> None:
        if got is None:
            return
        cur = best.get((cve, label))
        if cur is None or got[0] < cur[0]:
            best[(cve, label)] = got

    def evaluate(kind: str, groups: Mapping[str, tuple], key: str, label: str, inst: str, ctx: Optional[str]) -> None:
        g = groups.get(key)
        if not g:
            return
        memo = (kind, key, label, inst, ctx)
        if memo in done:                                        # the same package/version again (another arch or binary)
            return
        done.add(memo)
        hit = False
        for cve, stmts in g:
            k = kev.get(cve)
            if k is None:
                continue
            hit = True
            take(label, cve, _decide(label, cve, stmts, inst, cmp, ctx, k, dating_ok))
        if hit:
            relevant.add((kind, label))

    for r in rows:
        rkey = S.kernel_key(res, r)
        if rkey is None and r.src not in src_groups and r.name not in bin_groups:
            continue                                            # not KEV-relevant for the scope: nothing it says matters
        ctxs = []
        if is_esm_version(r.evr) or is_esm_version(r.srcevr):
            ctxs.append("esm_package")
        if meta is not None and res.family == "rpm":
            if r.name in meta.foreign:
                ctxs.append("foreign_signature")
            if r.name in meta.modular:
                ctxs.append("modular_package")
        if res.family == "rpm" and is_modular_evr(r.evr) and "modular_package" not in ctxs:
            ctxs.append("modular_package")
        if rkey is not None:                                    # a kernel-source row: only the running image counts
            if r is not owner and r != owner:
                continue
            if kreason == "livepatch":
                ctxs.append("livepatch")
            ctx = min(ctxs, key=_RANK.__getitem__) if ctxs else None
            if res.family == "deb":
                evaluate("source", src_groups, rkey, rkey, r.evr, ctx)        # the BINARY version of the image
            else:                                               # fix rows may be keyed by any image alias
                for alias in sorted(S.RPM_KERNEL_IMAGES):
                    evaluate("binary", bin_groups, alias, r.name, r.evr, ctx)
            continue
        ctx = min(ctxs, key=_RANK.__getitem__) if ctxs else None
        evaluate("source", src_groups, r.src, r.src, r.srcevr, ctx)
        evaluate("binary", bin_groups, r.name, r.name, r.evr, ctx)

    kernel_blind = False
    if kreason == "kernel_unknown":
        if res.family == "rpm":                                 # every alias key, one label (the installed image's name)
            installed = sorted({r.name for r in rows if r.name in S.RPM_KERNEL_IMAGES})
            targets = [(key, installed[0] if installed else "kernel") for key in kernel_fix_keys]
        else:
            wanted = {S.kernel_key(res, r) for r in rows if S.is_kernel_image_row(res, r)}
            targets = [(key, key) for key in ([k for k in kernel_fix_keys if k in wanted] or kernel_fix_keys)]
        for key, label in targets:
            for cve, stmts in kernel_groups[key]:
                k = kev.get(cve)
                if k is None:
                    continue
                kernel_blind = True
                relevant.add(("kernel", label))
                take(label, cve, _decide(label, cve, stmts, "", cmp, "kernel_unknown", k, dating_ok))

    opens, unknown, nofix = [], [], []
    for (_cve, _label), (_sk, kind, payload) in sorted(best.items(), key=lambda kv: kv[0]):
        (opens if kind == "open" else unknown if kind == "unknown" else nofix).append(payload)
    exact = not any(u.reason in ("kernel_unknown", "livepatch") for u in unknown) and not kernel_blind

    third: Optional[bool] = None
    if meta is not None:
        if res.family == "deb":
            third = S.third_party_from_origins(res.vendor, meta.apt_origins) if meta.apt_origins is not None else None
        else:
            third = bool(meta.foreign)
    notes = ["basis:distro_packages_only", "basis:installed_versions", "basis:advisory_feed_tls_only"]
    if nofix:
        notes.append("basis:no_fix_not_counted")
    if res.family == "deb" or meta is None:
        notes.append("basis:package_origin_unverified")
    if third:
        notes.append("basis:third_party_repositories_present")
    if res.vendor == "rhel":
        notes.append("basis:rhel_standard_stream_assumed")
    notes.sort(key=S.NOTE_ORDER.index)

    return MatchResult(status="ok", scope=scope, open=tuple(opens), unknown=tuple(unknown), no_fix=tuple(nofix),
                       relevant=len(relevant), third_party_sources=third, notes=tuple(notes), exact=exact,
                       manifest_sha=host.manifest_sha, manifest_count=len(host.rows), primary=prim,
                       dating=tuple(sorted(have.values(), key=lambda d: (d.source, d.id))), kev_snapshot=ksnap,
                       valid_until=valid_until)


__all__ = ["CAP_NO_FIX", "CAP_OPEN", "CAP_UNKNOWN", "FixIndex", "MatchResult", "NoFixItem", "OpenItem", "UnknownItem",
           "match_host", "Row"]
