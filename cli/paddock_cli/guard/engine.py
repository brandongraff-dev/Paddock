# SPDX-License-Identifier: AGPL-3.0-or-later
"""The engine: run checks over a ScanContext and build a Report (contract 3.3, 3.10, 3.11 H4, D9, D13).

``run_checks`` never raises for a bad file or a misbehaving check: it records ``errors`` and
``skipped`` and marks the report ``complete: false``. Tiers decide which checks run; a finding
blocks only when its confidence is ``high``, its severity reaches ``fail_on`` and it is neither
suppressed nor baselined. Delta mode (``ctx.base``) hides findings whose fingerprint is present in
a scan of the base ref.
"""
from __future__ import annotations

import hashlib
import re
import signal
import threading
import time
from dataclasses import dataclass
from typing import Any, Callable, Iterable, Sequence

from paddock_cli.guard import context as context_mod
from paddock_cli.guard import files, model, prompts, registry, rulepack, suppress, textsafe
from paddock_cli.guard.errors import GuardError, UsageError
from paddock_cli.guard.model import GuardFinding, Hit, Report
from paddock_cli.guard.registry import Check

_DATA_KEY = re.compile(r"^[a-z][a-z0-9_]{0,30}$")
_DATA_VAL = re.compile(r"^[A-Za-z0-9_@+=,~./:-]{0,80}$")
_MAX_FINDINGS_PER_CHECK = 2000


@dataclass(frozen=True)
class Budgets:
    """Hard per-call CPU budget and per-check wall budget per run (3.11 H4)."""

    per_file_cpu: float = 5.0
    per_check: float = 20.0


class _CpuTimeout(BaseException):
    pass


class _WallTimeout(BaseException):
    pass


def _on_wall(signum: int, frame: Any) -> None:
    raise _WallTimeout()


def _on_cpu(signum: int, frame: Any) -> None:
    raise _CpuTimeout()


def timers_available() -> bool:
    return (hasattr(signal, "setitimer") and hasattr(signal, "ITIMER_VIRTUAL")
            and threading.current_thread() is threading.main_thread())


class _Limiter:
    """Arms ``setitimer`` around one check call; handlers are installed once per run."""

    def __init__(self) -> None:
        self.enabled = timers_available()
        self._old: tuple[Any, Any] | None = None

    def __enter__(self) -> "_Limiter":
        if self.enabled:
            self._old = (signal.signal(signal.SIGALRM, _on_wall), signal.signal(signal.SIGVTALRM, _on_cpu))
        return self

    def __exit__(self, *exc: object) -> None:
        if self.enabled and self._old is not None:
            signal.setitimer(signal.ITIMER_REAL, 0)
            signal.setitimer(signal.ITIMER_VIRTUAL, 0)
            signal.signal(signal.SIGALRM, self._old[0])
            signal.signal(signal.SIGVTALRM, self._old[1])

    def run(self, fn: Callable[[], Any], cpu: float, wall: float) -> Any:
        if not self.enabled:
            return fn()
        signal.setitimer(signal.ITIMER_REAL, max(wall, 0.001))
        signal.setitimer(signal.ITIMER_VIRTUAL, max(cpu, 0.001))
        try:
            return fn()
        finally:
            signal.setitimer(signal.ITIMER_REAL, 0)
            signal.setitimer(signal.ITIMER_VIRTUAL, 0)


class _Collector:
    """Runs checks over one context and returns the raw (check, hit) pairs."""

    def __init__(self, ctx: context_mod.ScanContext, budgets: Budgets, clock: Callable[[], float],
                 deadline_at: float | None, limiter: _Limiter):
        self.ctx = ctx
        self.budgets = budgets
        self.clock = clock
        self.deadline_at = deadline_at
        self.limiter = limiter
        self.elapsed: dict[str, float] = {}
        self.dead: set[str] = set()
        self.hits: list[tuple[Check, Hit]] = []
        self.deadline_hit = False
        self.sup_files: dict[str, list[suppress.Suppression]] = {}
        self.sup_notes: list[str] = []

    def _past_deadline(self) -> bool:
        if self.deadline_hit:
            return True
        if self.deadline_at is not None and self.clock() >= self.deadline_at:
            self._flag_deadline()
        return self.deadline_hit

    def _flag_deadline(self) -> None:
        if not self.deadline_hit:
            self.deadline_hit = True
            self.ctx.error("", "", "deadline_exceeded")
            self.ctx.add_note("incomplete: the time budget was exhausted before every check finished", incomplete=True)

    def call(self, check: Check, fv: Any) -> None:
        if check.id in self.dead or self._past_deadline():
            return
        remaining = self.budgets.per_check - self.elapsed.get(check.id, 0.0)
        if remaining <= 0:
            self._flag_check(check, fv)
            return
        wall = remaining
        if self.deadline_at is not None:
            wall = min(wall, max(self.deadline_at - self.clock(), 0.001))
        t0 = self.clock()
        file = fv.path if fv is not None else ""
        result: list[Any] = []
        try:
            result = list(self.limiter.run(lambda: check.run(self.ctx, fv) or [], self.budgets.per_file_cpu, wall))  # type: ignore[misc]
        except _CpuTimeout:
            self.ctx.error(check.id, file, "file_timed_out")
        except _WallTimeout:
            if self.deadline_at is not None and self.clock() >= self.deadline_at:
                self._flag_deadline()
            else:
                self._flag_check(check, fv)
        except Exception as exc:  # noqa: BLE001  (a check must never abort the run)
            self.ctx.error(check.id, file, type(exc).__name__)
        finally:
            self.elapsed[check.id] = self.elapsed.get(check.id, 0.0) + max(self.clock() - t0, 0.0)
        if self.elapsed[check.id] > self.budgets.per_check and check.id not in self.dead:
            self._flag_check(check, fv)
        for h in result[:_MAX_FINDINGS_PER_CHECK]:
            self.hits.append((check, h))
        if len(result) > _MAX_FINDINGS_PER_CHECK:
            self.ctx.add_note("%s: more than %d findings in one call; the rest are not shown"
                              % (check.id, _MAX_FINDINGS_PER_CHECK))

    def _flag_check(self, check: Check, fv: Any) -> None:
        if check.id not in self.dead:
            self.dead.add(check.id)
            self.ctx.error(check.id, fv.path if fv is not None else "", "check_timed_out")

    def collect(self, selected: Sequence[Check], changed: set[str] | None) -> None:
        file_checks = [c for c in selected if c.scope == "file"]
        proj_checks = [c for c in selected if c.scope == "project"]
        if file_checks:
            wants_build = any(c.include_build for c in file_checks)
            for path in self.ctx.list_paths(include_build=wants_build):
                if self._past_deadline():
                    break
                if changed is not None and path not in changed:
                    continue
                build = context_mod._is_build_path(path)
                matching = [c for c in file_checks if c.id not in self.dead and (not build or c.include_build)
                            and files.match_any(c.globs, path)]
                if not matching:
                    continue
                fv = self.ctx.read(path, big_ok=any(c.big_ok for c in matching))
                if fv is None:
                    continue
                if "paddock:ignore" in fv.text:
                    sups, snotes = suppress.scan_suppressions(fv)
                    self.sup_files[path] = sups
                    self.sup_notes.extend(snotes)
                wide = None
                for c in matching:
                    if fv.streamed and not c.big_ok:
                        continue
                    if c.long_lines_ok:
                        if wide is None:
                            wide = fv.with_long_lines()
                        self.call(c, wide)
                    else:
                        self.call(c, fv)
        for c in proj_checks:
            if self._past_deadline():
                break
            if changed is not None and c.triggers and not any(
                    files.match_any(c.triggers, p) for p in changed):
                continue
            self.call(c, None)


def _norm_changed(changed: Iterable[str] | None) -> set[str] | None:
    if changed is None:
        return None
    return {c for c in (model.norm_relpath(p) for p in changed if isinstance(p, str)) if c}


def _resolve_only(only: Iterable[str] | None, checks: Sequence[Check]) -> set[str] | None:
    if not only:
        return None
    wanted: set[str] = set()
    for raw in only:
        key = raw.strip()
        if not key:
            continue
        up = key.upper()
        hit = [c.id for c in checks if c.id == key or c.pack == up or ("PG-" + c.pack) == up or ("PGX-" + c.pack) == up]
        if not hit:
            raise UsageError("unknown check or pack: %s" % textsafe.safe_text(key, cap=60))
        wanted.update(hit)
    return wanted


def _clean_data(data: Any) -> dict[str, Any]:
    out: dict[str, Any] = {}
    if not isinstance(data, dict):
        return out
    for k, v in data.items():
        if not isinstance(k, str) or not _DATA_KEY.match(k):
            continue
        if isinstance(v, bool):
            out[k] = v
        elif isinstance(v, int) and -10**12 < v < 10**12:
            out[k] = v
        elif isinstance(v, str) and _DATA_VAL.match(v):
            out[k] = v
    return out


def _int_or_none(v: Any) -> int | None:
    return v if isinstance(v, int) and not isinstance(v, bool) and 0 < v < 10**9 else None


def _make_finding(check: Check, tier: str, evidence_label: str, hit: Any, cfg: Any,
                  closed: set[str]) -> GuardFinding | None:
    if not isinstance(hit, Hit):
        return None
    file = model.norm_relpath(hit.file) if isinstance(hit.file, str) else None
    if file is None or not isinstance(hit.anchor, str):
        return None
    line = _int_or_none(hit.line)
    end = _int_or_none(hit.end_line)
    data = _clean_data(hit.data)
    conf = tier
    cap = data.get("tier_cap")
    if cap in ("medium", "low") and model.tier_rank(conf) > model.tier_rank(cap):
        conf = cap
    uid = data.get("unverified_id")
    if isinstance(uid, str) and uid not in closed and conf == "high":
        conf = "medium"
    sev = cfg.severity_for(check.id, check.severity)
    title = textsafe.safe_text(check.title, cap=200, escape=False) or check.id
    fp = model.fingerprint(check.id, file, hit.anchor[:300])
    f = GuardFinding(
        fingerprint=fp, check_id=check.id, title=title, severity=sev, confidence=conf, blocking=False,
        file=textsafe.cap(textsafe.clean(file), 300), line=line, end_line=end,
        evidence=textsafe.safe_text(hit.evidence, cap=200), message=title,
        fix_hint=textsafe.safe_text(check.fix_hint, cap=1200, escape=False), agent_prompt="",
        fixer=check.fixer, cwe=check.cwe, tier_evidence=evidence_label, status="open", data=data,
        source_path=file)
    f.agent_prompt = prompts.render(check, f)
    return f


def _meta_note(tier: str, ran: int, off: list[str]) -> str:
    shown = ", ".join(off[:12]) + (" and %d more" % (len(off) - 12) if len(off) > 12 else "")
    return ("%s: %d checks ran at tier %s; %d checks are off at this tier (%s); no findings is not a safety result"
            % (model.META_CHECKS_OFF, ran, tier, len(off), shown or "none"))


def run_checks(ctx: context_mod.ScanContext, *, tier: str = "high", only: Iterable[str] | None = None,
               changed: Sequence[str] | None = None, deadline: float | None = None,
               budgets: Budgets | None = None, clock: Callable[[], float] | None = None,
               use_baseline: bool = True, baseline_ref: str | None = None) -> Report:
    """Run the registered checks over ``ctx`` and return the report.

    ``deadline`` is a wall budget in seconds for the whole call (hooks pass ``timeout - 10``);
    ``changed`` restricts file checks to those paths (project checks re-run only when a changed
    path matches their ``triggers``); ``baseline_ref`` reads ``.paddock/baseline.json`` from that
    git ref so a pull request cannot grow the baseline it is judged by.
    """
    if tier not in model.TIERS:
        raise UsageError("unknown tier")
    registry.discover()
    cfg = ctx.cfg
    clock = clock or time.monotonic
    deadline_at = clock() + deadline if deadline is not None else None
    budgets = budgets or Budgets()

    scope = "staged" if ctx.staged else ("changed" if changed is not None else "full")
    if changed is None and ctx.staged:
        changed = ctx.staged_files()
    changed_set = _norm_changed(changed)
    report = Report(mode={"tier": tier, "scope": scope, "base": ctx.base, "offline": bool(ctx.offline),
                          "fail_on": cfg.fail_on})
    report.first_line_notices = list(cfg.notices)
    report.config_changes = cfg.config_changes()
    report.origin = {"root_sha": hashlib.sha256(ctx.root.encode("utf-8", "replace")).hexdigest()[:32]}

    for module, cls in registry.import_errors():
        ctx.error(module, "", "import:" + cls)

    all_checks = list(registry.all_checks())
    trusted_hashes = cfg.prompt.trusted_packs if cfg.user_config_trusted else ()
    pchecks, pnotes, perrs = rulepack.load_project_packs(
        ctx.root, trusted_hashes=trusted_hashes, timer_ok=rulepack.timer_available())
    for n in pnotes:
        ctx.add_note(n, incomplete=(n == "pack-skipped-no-timer"))
    for e in perrs:
        ctx.add_note("rule pack not loaded: " + e, incomplete=True)
    seen_ids = {c.id for c in all_checks}
    all_checks += [c for c in pchecks if c.id not in seen_ids]

    wanted = _resolve_only(only, all_checks)
    selected: list[tuple[Check, str, str]] = []
    off: list[str] = []
    for c in all_checks:
        if wanted is not None and c.id not in wanted:
            continue
        if not cfg.check_enabled(c.id):
            continue
        eff, label = registry.effective_tier(c)
        if model.tier_rank(eff) >= model.tier_rank(tier):
            selected.append((c, eff, label))
        else:
            off.append(c.id)
    tiers = {c.id: (eff, label) for c, eff, label in selected}
    report.checks_run = sorted(c.id for c, _, _ in selected)
    report.checks_off_at_tier = sorted(off)

    closed = registry.load_verified()
    with _Limiter() as limiter:
        head = _Collector(ctx, budgets, clock, deadline_at, limiter)
        head.collect([c for c, _, _ in selected], changed_set)
        report.timings = dict(head.elapsed)

        findings: dict[str, GuardFinding] = {}
        by_id = {c.id: c for c, _, _ in selected}
        for check, hit in head.hits:
            eff, label = tiers[check.id]
            f = _make_finding(check, eff, label, hit, cfg, closed)
            if f is None:
                ctx.error(check.id, "", "invalid_hit")
                continue
            prev = findings.get(f.fingerprint)
            if prev is None or (f.line or 0) < (prev.line or 0):
                findings[f.fingerprint] = f
        flist = list(findings.values())

        sup_records = _apply_suppressions(ctx, head, flist, by_id)
        _apply_baseline(ctx, flist, use_baseline, baseline_ref)
        for f in flist:
            f.blocking = (f.status == "open" and f.confidence == "high"
                          and model.severity_rank(f.severity) >= model.severity_rank(cfg.fail_on))
        hidden = _delta(ctx, report, flist, by_id, tiers, sup_records, budgets, clock, deadline_at, limiter, closed)
    # ---- finalise ----------------------------------------------------------------------------
    report.findings = sorted((f for f in flist if f.fingerprint not in hidden), key=GuardFinding.sort_key)
    for n in ctx.notes:
        if n not in report.notes:
            report.notes.append(n)
    report.notes.insert(0, _meta_note(tier, len(selected), report.checks_off_at_tier))
    report.skipped = list(ctx.skipped)
    report.errors = list(ctx.errors)
    report.complete = ctx.complete
    return report


# ---- suppression ---------------------------------------------------------------------------------
def _apply_suppressions(ctx: context_mod.ScanContext, head: _Collector, findings: list[GuardFinding],
                        by_id: dict[str, Check]) -> list[dict[str, Any]]:
    records: list[dict[str, Any]] = []
    cache: dict[str, list[suppress.Suppression]] = dict(head.sup_files)
    for n in head.sup_notes:
        ctx.add_note(n)
    for f in findings:
        real = f.source_path or f.file
        if real not in cache:
            fv = ctx.read(real)
            if fv is not None and "paddock:ignore" in fv.text:
                sups, notes = suppress.scan_suppressions(fv)
                cache[real] = sups
                for n in notes:
                    ctx.add_note(n)
            else:
                cache[real] = []
    seen_notes: set[str] = set()
    for f in findings:
        sup = suppress.match(cache.get(f.source_path or f.file, []), f.check_id, f.line)
        if sup is None:
            continue
        check = by_id.get(f.check_id)
        if check is not None and not check.inline_suppressible:
            msg = "inline suppression for %s at %s:%s ignored (the check is not inline-suppressible; use the baseline or .paddock/guard.toml)" % (
                f.check_id, textsafe.safe_text(f.file, cap=120), f.line if f.line else 0)
            if msg not in seen_notes:
                seen_notes.add(msg)
                ctx.add_note(msg)
            continue
        f.status = "suppressed"
        records.append({"kind": "inline", "file": f.file, "check_id": f.check_id, "line": sup.line,
                        "reason": sup.reason, "fingerprint": f.fingerprint})
    return records


def _apply_baseline(ctx: context_mod.ScanContext, findings: list[GuardFinding],
                    use_baseline: bool, baseline_ref: str | None) -> suppress.Baseline | None:
    if not use_baseline:
        return None
    try:
        bl, notes = suppress.load_baseline(ctx.root, ref=baseline_ref)
    except GuardError as exc:
        bl, notes = None, ["baseline not read: %s" % textsafe.safe_text(str(exc), cap=120)]
    for n in notes:
        ctx.add_note(n)
    if bl is None:
        return None
    fps = bl.fingerprints
    for f in findings:
        if f.status == "open" and f.fingerprint in fps:
            f.status = "baselined"
    return bl


# ---- delta ---------------------------------------------------------------------------------------
def _config_diff(ctx: context_mod.ScanContext, base_path: str) -> None:
    """Note how this run's configuration differs from the one committed at the base ref (3.6)."""
    from paddock_cli.guard import config as config_mod

    try:
        base_cfg = config_mod.load_config(base_path, hook_mode=True)
    except GuardError:
        return
    now, then = ctx.cfg.config_changes(), base_cfg.config_changes()
    parts: list[str] = []
    for key in ("disabled_checks", "excluded", "severity_overrides", "packages"):
        added = [x for x in now[key] if x not in then[key]]
        removed = [x for x in then[key] if x not in now[key]]
        if added:
            parts.append("%s +%s" % (key, ", ".join(textsafe.safe_text(x, cap=60) for x in added[:5])))
        if removed:
            parts.append("%s -%s" % (key, ", ".join(textsafe.safe_text(x, cap=60) for x in removed[:5])))
    if parts:
        ctx.add_note("configuration differs from the base ref: " + "; ".join(parts))


def _delta(ctx: context_mod.ScanContext, report: Report, findings: list[GuardFinding],
           by_id: dict[str, Check], tiers: dict[str, tuple[str, str]], sup_records: list[dict[str, Any]],
           budgets: Budgets, clock: Callable[[], float], deadline_at: float | None, limiter: _Limiter,
           closed: set[str]) -> set[str]:
    """Hide legacy findings; returns the fingerprints to drop from the report."""
    if ctx.base is None:
        return set()
    try:
        bt = ctx.base_tree
    except GuardError as exc:
        ctx.add_note("base tree unavailable (%s): delta mode not applied, every finding is shown"
                     % textsafe.safe_text(str(exc), cap=120), incomplete=True)
        return set()
    assert bt is not None
    if bt.partial_missing:
        ctx.add_note("incomplete: base_partial (%d file(s) are missing from the base archive, for example through "
                     "export-ignore); findings in them are not reported as new" % len(bt.partial_missing), incomplete=True)
    missing = set(bt.partial_missing)
    _config_diff(ctx, bt.path)
    head_check_ids = sorted({f.check_id for f in findings})
    base_fps: set[str] = set()
    base_sups: dict[str, list[suppress.Suppression]] = {}
    if head_check_ids:
        with context_mod.ScanContext.open(bt.path, ctx.cfg, offline=True, no_state=True) as bctx:
            bcol = _Collector(bctx, budgets, clock, deadline_at, limiter)
            bcol.collect([by_id[i] for i in head_check_ids if i in by_id], None)
            for check, hit in bcol.hits:
                eff, label = tiers[check.id]
                bf = _make_finding(check, eff, label, hit, ctx.cfg, closed)
                if bf is not None:
                    base_fps.add(bf.fingerprint)
            base_sups = bcol.sup_files
            if bctx.errors:
                ctx.add_note("the base scan did not finish; delta results may include legacy findings", incomplete=True)
    # suppression and baseline growth versus the base ref
    added: list[dict[str, Any]] = []
    for rec in sup_records:
        bs = base_sups.get(rec["file"])
        if bs is None:
            fv, _why = files.read_file(bt.path, rec["file"])
            bs = suppress.scan_suppressions(fv)[0] if fv is not None and "paddock:ignore" in fv.text else []
        if not any(s.check_id == rec["check_id"] and s.reason == rec["reason"] for s in bs):
            added.append(rec)
    try:
        head_bl, _n = suppress.load_baseline(ctx.root)
        base_bl, _n2 = suppress.load_baseline(bt.path)
    except GuardError:
        head_bl = base_bl = None
    if head_bl is not None:
        before = base_bl.fingerprints if base_bl is not None else set()
        for e in head_bl.entries:
            if e.fingerprint not in before:
                report.baseline_growth += 1
                added.append({"kind": "baseline", "file": e.file, "check_id": e.check_id, "line": None,
                              "reason": e.reason, "fingerprint": e.fingerprint})
    report.suppressions_added = added
    hidden = {f.fingerprint for f in findings if f.fingerprint in base_fps or f.file in missing}
    legacy = sum(1 for f in findings if f.fingerprint in base_fps)
    if legacy:
        ctx.add_note("%d legacy finding(s) hidden by delta mode (already present at the base ref)" % legacy)
    return hidden
