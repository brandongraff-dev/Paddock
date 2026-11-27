# SPDX-License-Identifier: AGPL-3.0-or-later
"""TOML rule packs: loader, structural regex lint and trust (contract 3.7, D22).

A pack is plain data run at confidence ``medium`` or ``low`` only. Packs shipped in the wheel are
trusted; a pack under ``.paddock/rules/`` is untrusted (its words never reach the user's agent)
unless its sha256 is listed in the user-level config. Every pattern passes a structural lint over
``re._parser`` output and a load-time pump test, because a cloned repository must not be able to
hang or speak through Guard.
"""
from __future__ import annotations

import hashlib
import os
import re
import tomllib
from typing import Any

from paddock_cli.guard import files, textsafe
from paddock_cli.guard.errors import GuardError
from paddock_cli.guard.model import Hit, norm_relpath
from paddock_cli.guard.registry import PACK_ID_RE, Check, template_fields

try:  # the regex parser moved to a private module in 3.11
    from re import _constants as _sre_constants
    from re import _parser as _sre_parse
except ImportError:  # pragma: no cover
    import sre_constants as _sre_constants  # type: ignore[no-redef]
    import sre_parse as _sre_parse  # type: ignore[no-redef]

MAX_PACK_BYTES = 100 * 1024
MAX_RULES = 200
MAX_PATTERN = 400
MAX_BOUNDED = 200
MAX_LINE = 4000
_PUMP_SIZES = (400, 800)
_PUMP_MIN_SECONDS = 0.05

_PACK_KEYS = {"id", "version"}
_RULE_KEYS = {"id", "title", "severity", "confidence", "files", "exclude", "pattern", "negative_pattern",
              "why", "fix_hint", "agent_prompt"}
_PACK_ID = re.compile(r"^[a-z0-9-]{3,40}$")
_SEV = ("info", "low", "medium", "high", "critical")
_SEV_RANK = {s: i for i, s in enumerate(_SEV)}

UNTRUSTED_WHY = "A rule pack in this repository flagged this code; its text is not shown because the pack is untrusted."
UNTRUSTED_FIX = "Review the code at the reported location and fix it if it is a real problem."
UNTRUSTED_PROMPT = (
    "A rule pack in this repository flagged the code at {file}:{line}. The rule text is not shown because the "
    "pack is untrusted.\n"
    "1. Review the code at that location and fix it if it is a real problem."
)
DEFAULT_PROMPT = "Review the code at {file}:{line} and fix the problem described by the rule title."


class PackError(GuardError):
    """A pack or rule was rejected; the message names the rule id and the reason, never the pattern."""


# ---- regex lint ------------------------------------------------------------------------------
_REPEATS = {_sre_constants.MAX_REPEAT, _sre_constants.MIN_REPEAT}
if hasattr(_sre_constants, "POSSESSIVE_REPEAT"):
    _REPEATS.add(_sre_constants.POSSESSIVE_REPEAT)
_MAXREPEAT = _sre_constants.MAXREPEAT
_ALLOWED_FLAGS = re.IGNORECASE | re.MULTILINE | re.UNICODE
_ANY = None  # first-character set meaning "any character"


def _items(sub: Any) -> list[tuple[Any, Any]]:
    return list(sub)


def _first(sub: Any, icase: bool) -> tuple[frozenset[int] | None, bool]:
    """(first-character codepoints or None for any, nullable) for a parsed sub-pattern."""
    acc: set[int] = set()
    for op, av in _items(sub):
        name = str(op)
        if op == _sre_constants.LITERAL:
            acc.add(av)
            if icase:
                acc.update({ord(chr(av).lower()), ord(chr(av).upper())})
            return frozenset(acc), False
        if op == _sre_constants.NOT_LITERAL or op == _sre_constants.ANY or op == _sre_constants.CATEGORY:
            return _ANY, False
        if op == _sre_constants.IN:
            chars: set[int] = set()
            for iop, iav in av:
                if iop == _sre_constants.LITERAL:
                    chars.add(iav)
                elif iop == _sre_constants.RANGE:
                    if iav[1] - iav[0] > 255:
                        return _ANY, False
                    chars.update(range(iav[0], iav[1] + 1))
                else:
                    return _ANY, False
            if icase:
                chars |= {ord(chr(c).lower()) for c in chars} | {ord(chr(c).upper()) for c in chars}
            acc |= chars
            return frozenset(acc), False
        if op == _sre_constants.SUBPATTERN:
            f, nullable = _first(av[-1], icase)
            if f is _ANY:
                return _ANY, False
            acc |= f
            if not nullable:
                return frozenset(acc), False
            continue
        if op == _sre_constants.BRANCH:
            nullable_any = False
            for br in av[1]:
                f, nl = _first(br, icase)
                if f is _ANY:
                    return _ANY, False
                acc |= f
                nullable_any = nullable_any or nl
            if not nullable_any:
                return frozenset(acc), False
            continue
        if op in _REPEATS:
            lo, _hi, body = av
            f, nl = _first(body, icase)
            if f is _ANY:
                return _ANY, False
            acc |= f
            if lo > 0 and not nl:
                return frozenset(acc), False
            continue
        if name in ("AT", "ASSERT", "ASSERT_NOT"):
            continue
        return _ANY, False
    return frozenset(acc), True


def _overlap(a: frozenset[int] | None, b: frozenset[int] | None) -> bool:
    return a is _ANY or b is _ANY or bool(a & b)  # type: ignore[operator]


class _Stats:
    __slots__ = ("unbounded", "max_nested", "has_branch_overlap", "problem")

    def __init__(self) -> None:
        self.unbounded = 0
        self.max_nested = 1
        self.has_branch_overlap = False
        self.problem: str | None = None


def _walk(sub: Any, st: _Stats, icase: bool, in_repeat: int, depth: int) -> int:
    """Walk a sub-pattern; return the largest product of nested repeat maxima inside it."""
    if depth > 30:
        st.problem = "pattern nests too deeply"
        return 1
    best = 1
    for op, av in _items(sub):
        if op in _REPEATS:
            lo, hi, body = av
            unb = hi == _MAXREPEAT
            if unb:
                st.unbounded += 1
                if st.unbounded > 1:
                    st.problem = st.problem or "more than one unbounded quantifier"
            elif hi > MAX_BOUNDED:
                st.problem = st.problem or "bounded repetition above %d" % MAX_BOUNDED
            mark = st.unbounded
            inner = _walk(body, st, icase, in_repeat + (1 if hi > 1 else 0), depth + 1)
            if hi > 1:
                if st.unbounded > mark:
                    st.problem = st.problem or "nested quantifier"
                if _first(body, icase)[1]:
                    st.problem = st.problem or "quantified group may match empty"
            if unb and inner > 1:
                st.problem = st.problem or "nested quantifier"
            prod = (10 ** 6 if unb else max(1, hi)) * inner
            if not unb and prod > 1000:
                st.problem = st.problem or "nested repetition multiplies past 1000"
            best = max(best, prod)
        elif op == _sre_constants.BRANCH:
            firsts = []
            nullable = False
            for br in av[1]:
                f, nl = _first(br, icase)
                firsts.append(f)
                nullable = nullable or nl
                best = max(best, _walk(br, st, icase, in_repeat, depth + 1))
            if in_repeat:
                if nullable:
                    st.problem = st.problem or "alternation under a quantifier may match empty"
                for i in range(len(firsts)):
                    for j in range(i + 1, len(firsts)):
                        if _overlap(firsts[i], firsts[j]):
                            st.problem = st.problem or "alternation under a quantifier with overlapping branches"
        elif op == _sre_constants.SUBPATTERN:
            add_flags, del_flags = av[1], av[2]
            if add_flags & ~_ALLOWED_FLAGS:
                st.problem = st.problem or "inline flag not allowed"
            best = max(best, _walk(av[-1], st, icase or bool(add_flags & re.IGNORECASE), in_repeat, depth + 1))
        elif op in (_sre_constants.GROUPREF, _sre_constants.GROUPREF_EXISTS):
            st.problem = st.problem or "backreference"
        elif str(op) in ("ASSERT", "ASSERT_NOT", "ATOMIC_GROUP"):
            sub2 = av[-1] if isinstance(av, tuple) else av
            best = max(best, _walk(sub2, st, icase, in_repeat, depth + 1))
    return best


def lint_pattern(pattern: str) -> str | None:
    """Reason a pattern is refused, or None. Structural: nothing is matched against text."""
    if not isinstance(pattern, str) or not pattern:
        return "empty pattern"
    if len(pattern) > MAX_PATTERN:
        return "longer than %d characters" % MAX_PATTERN
    try:
        parsed = _sre_parse.parse(pattern)
    except (re.error, RecursionError, OverflowError, ValueError, MemoryError):
        return "not a valid regular expression"
    flags = parsed.state.flags
    if flags & ~_ALLOWED_FLAGS:
        return "flags other than (?i) and (?m) are not allowed"
    st = _Stats()
    _walk(parsed, st, bool(flags & re.IGNORECASE), 0, 0)
    return st.problem


def _literal_prefix(pattern: str) -> str:
    prefix = ""
    try:
        for op, av in _items(_sre_parse.parse(pattern)):
            if op == _sre_constants.LITERAL and len(prefix) < 40:
                prefix += chr(av)
            else:
                break
    except Exception:  # noqa: BLE001
        pass
    return prefix


_EXP_SIZES = (8, 10, 12, 14, 16, 18, 20)
_EXP_ABORT = 0.2


def _pump_ok(pattern: str, flags: int) -> bool:
    """Run the pattern on inputs pumped from its own literal prefix and reject super-linear growth.

    Two probes: small sizes that expose exponential backtracking (stopped as soon as one run is
    slow, so a catastrophic pattern costs at most a fraction of a second) and large sizes that
    expose quadratic growth (doubling n must not cost more than about 3.5x).
    """
    import time

    try:
        rx = re.compile(pattern, flags)
    except re.error:
        return False
    prefix = _literal_prefix(pattern)
    for ch in ("a", " ", "0", "/", "=", "-", "x"):
        prev = None
        for n in _EXP_SIZES:
            t0 = time.process_time()
            rx.search(prefix + ch * n + "!\u00e9")
            t = time.process_time() - t0
            if t > _EXP_ABORT:
                return False
            if prev is not None and t > 0.005 and t / max(prev, 1e-6) > 3.0:
                return False
            prev = t
        timings = []
        for n in _PUMP_SIZES:
            t0 = time.process_time()
            rx.search(prefix + ch * n + "!\u00e9")
            timings.append(time.process_time() - t0)
        lo, hi = timings
        if hi > _PUMP_MIN_SECONDS and hi / max(lo, 1e-6) > 3.5:
            return False
    return True


# ---- loading ---------------------------------------------------------------------------------
def pack_sha256(raw: bytes) -> str:
    """sha256 over the file bytes with line endings normalised to LF (D22)."""
    return hashlib.sha256(raw.replace(b"\r\n", b"\n")).hexdigest()


def _fail(rule_id: str | None, msg: str) -> PackError:
    return PackError(("%s: %s" % (rule_id, msg)) if rule_id else msg)


def _check_globs(rule_id: str, key: str, value: Any, *, required: bool) -> tuple[str, ...]:
    if value is None:
        if required:
            raise _fail(rule_id, "%s is required" % key)
        return ()
    if not isinstance(value, list) or (required and not value) or len(value) > 50:
        raise _fail(rule_id, "%s must be a non-empty list of globs" % key)
    out = []
    for g in value:
        if (not isinstance(g, str) or not g or g.startswith("/") or "\x00" in g or "\\" in g
                or ".." in g.split("/") or len(g) > 200):
            raise _fail(rule_id, "%s has an unsafe glob" % key)
        out.append(g)
    return tuple(out)


def _str(rule_id: str, key: str, value: Any, limit: int) -> str:
    if not isinstance(value, str) or len(value) > limit:
        raise _fail(rule_id, "%s must be a string of at most %d characters" % (key, limit))
    return value


def _make_run(rule_id: str, rx: re.Pattern[str], neg: re.Pattern[str] | None, exclude: tuple[str, ...]):
    def run(ctx: Any, fv: Any) -> list[Hit]:
        if fv is None or (exclude and files.match_any(exclude, fv.path)):
            return []
        hits: list[Hit] = []
        ordinal = 0
        for i, line in enumerate(fv.lines, start=1):
            if len(line) > MAX_LINE:
                continue
            m = rx.search(line)
            if not m or (neg is not None and neg.search(line)):
                continue
            ordinal += 1
            hits.append(Hit(file=fv.path, line=i, end_line=i, anchor="%s:%d" % (rule_id, ordinal),
                            evidence="pattern matched (%d characters)" % len(m.group(0)),
                            data={"rule": rule_id}))
        return hits

    return run


def load_pack_text(text: str, *, trusted: bool, origin: str = "pack") -> list[Check]:
    """Parse and validate one pack; returns its checks. Raises ``PackError`` naming the rule."""
    raw = text.encode("utf-8", "replace") if isinstance(text, str) else text
    if len(raw) > MAX_PACK_BYTES:
        raise _fail(None, "pack is larger than %d bytes" % MAX_PACK_BYTES)
    try:
        doc = tomllib.loads(raw.decode("utf-8", "replace"))
    except (tomllib.TOMLDecodeError, RecursionError, MemoryError, OverflowError, ValueError):
        raise _fail(None, "pack is not valid TOML") from None
    if not isinstance(doc, dict) or set(doc) - {"pack", "rule"}:
        raise _fail(None, "unknown top-level table")
    meta = doc.get("pack")
    if not isinstance(meta, dict) or set(meta) - _PACK_KEYS or "id" not in meta or "version" not in meta:
        raise _fail(None, "[pack] needs exactly id and version")
    pid = meta["id"]
    if not isinstance(pid, str) or not _PACK_ID.match(pid) or not isinstance(meta["version"], int):
        raise _fail(None, "pack id must match [a-z0-9-]{3,40} and version must be an integer")
    rules = doc.get("rule", [])
    if not isinstance(rules, list) or len(rules) > MAX_RULES:
        raise _fail(None, "a pack may hold at most %d rules" % MAX_RULES)
    prefix = "PGX-%s-" % pid.upper()
    out: list[Check] = []
    seen: set[str] = set()
    for r in rules:
        if not isinstance(r, dict):
            raise _fail(None, "rule must be a table")
        rid = r.get("id")
        if not isinstance(rid, str) or not rid.startswith(prefix) or not PACK_ID_RE.match(rid):
            raise _fail(rid if isinstance(rid, str) else None, "id must start with %s and end in -NNN" % prefix)
        if rid in seen:
            raise _fail(rid, "duplicate id")
        seen.add(rid)
        unknown = set(r) - _RULE_KEYS
        if unknown:
            raise _fail(rid, "unknown key %s" % sorted(unknown)[0])
        title = _str(rid, "title", r.get("title"), 2000)
        severity = r.get("severity")
        if severity not in _SEV:
            raise _fail(rid, "severity must be one of %s" % ", ".join(_SEV))
        confidence = r.get("confidence", "medium")
        if confidence not in ("medium", "low"):
            raise _fail(rid, "confidence must be medium or low (packs never run at high)")
        globs = _check_globs(rid, "files", r.get("files"), required=True)
        exclude = _check_globs(rid, "exclude", r.get("exclude"), required=False)
        pattern = _str(rid, "pattern", r.get("pattern"), 100000)
        neg_pat = r.get("negative_pattern")
        for key, pat in (("pattern", pattern), ("negative_pattern", neg_pat)):
            if pat is None:
                continue
            if not isinstance(pat, str):
                raise _fail(rid, "%s must be a string" % key)
            reason = lint_pattern(pat)
            if reason:
                raise _fail(rid, "%s rejected: %s" % (key, reason))
        why = _str(rid, "why", r.get("why", ""), 2000)
        fix_hint = _str(rid, "fix_hint", r.get("fix_hint", ""), 2000)
        prompt = _str(rid, "agent_prompt", r.get("agent_prompt", DEFAULT_PROMPT), 2000)
        try:
            flags = _sre_parse.parse(pattern).state.flags
            rx = re.compile(pattern)
            neg = re.compile(neg_pat) if neg_pat else None
        except (re.error, RecursionError, OverflowError, ValueError):
            raise _fail(rid, "pattern rejected: not a valid regular expression") from None
        if not _pump_ok(pattern, flags & (re.I | re.M)):
            raise _fail(rid, "pattern rejected: super-linear on pumped input")
        for f in template_fields(prompt):
            if not re.match(r"^[a-z][a-z0-9_]{0,30}$", f):
                raise _fail(rid, "agent_prompt has a template field that is not allowed")
        if trusted:
            title_c = textsafe.cap(textsafe.collapse_ws(textsafe.clean(title)), 120) or "Rule " + rid
            why_c = textsafe.cap(textsafe.collapse_ws(textsafe.clean(why)), 1200)
            fix_c = textsafe.cap(textsafe.collapse_ws(textsafe.clean(fix_hint)), 1200)
            prompt_c = textsafe.cap(textsafe.clean(prompt, keep_newlines=True), 1200)
            sev_c = severity
        else:
            title_c, why_c, fix_c, prompt_c = "Rule " + rid, UNTRUSTED_WHY, UNTRUSTED_FIX, UNTRUSTED_PROMPT
            sev_c = severity if _SEV_RANK[severity] <= _SEV_RANK["medium"] else "medium"
        out.append(Check(
            id=rid, title=title_c, pack=pid.upper(), severity=sev_c, proposed_tier=confidence, scope="file",
            globs=globs, why=why_c, fix_hint=fix_c, agent_prompt=prompt_c, origin=origin, trusted=trusted,
            run=_make_run(rid, rx, neg, exclude)))
    return out


def load_pack_file(path: str, *, trusted: bool, origin: str = "pack") -> list[Check]:
    """Load a shipped pack from the package directory (never a path inside a scanned tree)."""
    with open(path, "rb") as fh:
        raw = fh.read(MAX_PACK_BYTES + 1)
    return load_pack_text(raw.decode("utf-8", "replace"), trusted=trusted, origin=origin)


def timer_available() -> bool:
    """A hard per-file timer exists: main thread of a POSIX process with ``setitimer``."""
    import signal
    import threading

    return hasattr(signal, "setitimer") and threading.current_thread() is threading.main_thread()


def load_project_packs(root_real: str, *, trusted_hashes: tuple[str, ...] | list[str] = (),
                       timer_ok: bool | None = None) -> tuple[list[Check], list[str], list[str]]:
    """Load ``<root>/.paddock/rules/*.toml``. Returns (checks, notes, errors).

    Project packs are untrusted unless their sha256 is in ``trusted_hashes`` (user-level config).
    Each pack is reported with its sha256 so a user can pin it. Without a hard timer they are
    skipped with the note ``pack-skipped-no-timer``.
    """
    notes: list[str] = []
    errs: list[str] = []
    checks: list[Check] = []
    rules_dir = os.path.join(root_real, ".paddock", "rules")
    try:
        if os.path.islink(os.path.join(root_real, ".paddock")) or os.path.islink(rules_dir):
            return checks, notes, errs
        names = sorted(n for n in os.listdir(rules_dir) if n.endswith(".toml"))
    except OSError:
        return checks, notes, errs
    if not names:
        return checks, notes, errs
    if timer_ok is None:
        timer_ok = timer_available()
    if not timer_ok:
        notes.append("pack-skipped-no-timer")
        return checks, notes, errs
    trusted_set = {h.lower() for h in trusted_hashes}
    seen: set[str] = set()
    for name in names[:50]:
        rel = ".paddock/rules/" + name
        raw_view, why = _read_raw(root_real, rel)
        if raw_view is None:
            if why not in ("missing",):
                errs.append("%s: not read (%s)" % (textsafe.safe_text(name, cap=60), why))
            continue
        sha = pack_sha256(raw_view)
        trusted = sha in trusted_set
        notes.append("pack-sha256 %s %s%s" % (textsafe.safe_text(name, cap=60), sha, " trusted" if trusted else ""))
        try:
            loaded = load_pack_text(raw_view.decode("utf-8", "replace"), trusted=trusted, origin="project-pack")
        except PackError as exc:
            errs.append("%s: %s" % (textsafe.safe_text(name, cap=60), textsafe.safe_text(str(exc), cap=160)))
            continue
        for c in loaded:
            if c.id in seen:
                errs.append("%s: duplicate rule id %s" % (name, c.id))
                continue
            seen.add(c.id)
            checks.append(c)
    return checks, notes, errs


def _read_raw(root_real: str, rel: str) -> tuple[bytes | None, str | None]:
    with files.RootHandle(root_real) as h:
        fd, why, st = h.open_file(rel)
        if fd is None:
            return None, why
        try:
            data = os.read(fd, MAX_PACK_BYTES + 1)
        finally:
            os.close(fd)
    if len(data) > MAX_PACK_BYTES:
        return None, "oversize"
    return data, None
