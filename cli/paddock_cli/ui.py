"""Terminal output: plain ANSI, no dependencies.

Colour is on only when the stream is a TTY, ``NO_COLOR`` is unset (any value;
https://no-color.org), ``TERM`` is not ``dumb``, and ``--no-color`` was not
given. ``FORCE_COLOR`` turns it on for piped output (CI logs).
"""
from __future__ import annotations

import os
import re
import shutil
import sys
import textwrap
from typing import IO

from .model import KIND_TITLES, KINDS, SEVERITIES, Finding, ScanResult, rank

_SEV_STYLE = {
    "critical": "1;97;41",   # bold white on red
    "high": "1;31",
    "medium": "1;33",
    "low": "36",
    "info": "2",
}


def color_enabled(stream: IO[str], no_color_flag: bool = False) -> bool:
    if no_color_flag or "NO_COLOR" in os.environ:
        return False
    if os.environ.get("FORCE_COLOR") not in (None, "", "0"):
        return True
    if os.environ.get("TERM") == "dumb":
        return False
    try:
        return stream.isatty()
    except (AttributeError, ValueError):
        return False


def unicode_ok(stream: IO[str]) -> bool:
    enc = (getattr(stream, "encoding", None) or "").lower()
    return "utf" in enc


class Style:
    def __init__(self, color: bool, unicode: bool, width: int | None = None) -> None:
        self.color = color
        self.unicode = unicode
        self.width = max(60, min(width or shutil.get_terminal_size((100, 24)).columns, 120))

    def _c(self, code: str, s: str) -> str:
        return f"\x1b[{code}m{s}\x1b[0m" if self.color else s

    def bold(self, s: str) -> str: return self._c("1", s)
    def dim(self, s: str) -> str: return self._c("2", s)
    def red(self, s: str) -> str: return self._c("31", s)
    def green(self, s: str) -> str: return self._c("32", s)
    def yellow(self, s: str) -> str: return self._c("33", s)
    def cyan(self, s: str) -> str: return self._c("36", s)

    def sev(self, sev: str, label: str | None = None) -> str:
        text = (label or sev).upper()
        if sev == "critical" and self.color:
            text = f" {text} "
        return self._c(_SEV_STYLE.get(sev, "0"), text)

    @property
    def dot(self) -> str: return "●" if self.unicode else "*"
    @property
    def ok(self) -> str: return "✔" if self.unicode else "+"
    @property
    def bad(self) -> str: return "✖" if self.unicode else "x"
    @property
    def arrow(self) -> str: return "→" if self.unicode else "->"
    @property
    def rule(self) -> str: return "─" if self.unicode else "-"

    def wrap(self, text: str, indent: int, first: str = "") -> str:
        pad = " " * indent
        body = textwrap.fill(text, width=self.width, initial_indent=pad + first,
                             subsequent_indent=pad + " " * len(first))
        return body


_ANSI = re.compile(r"\x1b\[[0-9;]*m")


def visible_len(s: str) -> int:
    return len(_ANSI.sub("", s))


def _loc(f: Finding) -> str:
    return f"{f.file}:{f.line}" if f.line else f.file


def _finding_block(st: Style, f: Finding) -> list[str]:
    badge = st.sev(f.severity)
    head = "  " + badge
    pad_badge = " " * max(1, 12 - visible_len(head))
    title = st.bold(f.title)
    loc = st.dim(_loc(f))
    room = st.width - 12 - visible_len(title) - 2
    gap = max(2, room - visible_len(loc))
    lines = [f"{head}{pad_badge}{title}" + (" " * gap + loc if room > visible_len(loc) + 1 else "")]
    if room <= visible_len(loc) + 1:
        lines.append("            " + loc)
    if f.message:
        lines.append(st.dim(st.wrap(f.message, 12)))
    lines.append(st.wrap(f.why, 12, first=st.bold("why ") + " "))
    if f.fix:
        tag = st.green("fix") + "  "
        extra = st.dim("  (paddock fix)") if f.fixable else ""
        lines.append(textwrap.fill(f.fix, width=st.width, initial_indent="            " + tag,
                                   subsequent_indent=" " * 17) + extra)
    return lines


def render_report(res: ScanResult, st: Style, version: str, *, show_all: bool = False,
                  max_per_group: int = 25) -> str:
    out: list[str] = []
    root = os.path.basename(res.root.rstrip("/")) or res.root
    out.append("")
    out.append(f"  {st.bold('paddock')} {st.dim(version)}  {st.arrow}  {root}")
    bits = []
    s = res.stats
    if s.get("manifests") is not None:
        bits.append(f"{s.get('manifests', 0)} manifests, {s.get('packages', 0)} packages")
    if s.get("source_files"):
        bits.append(f"{s['source_files']} source files")
    bits.append(f"{s.get('files', 0)} files")
    out.append("  " + st.dim(" · ".join(bits)))
    out.append("")

    if not res.findings:
        out.append(f"  {st.green(st.ok)} {st.bold('Nothing found.')} "
                   "No known vulnerabilities, secrets or code issues in what was scanned.")
    for kind in KINDS:
        group = [f for f in res.findings if f.kind == kind]
        if not group:
            continue
        out.append(f"  {st.bold(KIND_TITLES[kind].upper())} {st.dim(f'({len(group)})')}")
        out.append("  " + st.dim(st.rule * (st.width - 4)))
        shown = group if show_all else group[:max_per_group]
        for f in shown:
            out.extend(_finding_block(st, f))
            out.append("")
        if len(shown) < len(group):
            out.append(st.dim(f"  … {len(group) - len(shown)} more (use --all to list everything)"))
            out.append("")

    out.append("  " + st.dim(st.rule * (st.width - 4)))
    out.append("  " + summary_line(res, st))
    fixable = sum(1 for f in res.findings if f.fixable)
    if fixable:
        out.append(f"  {st.green(st.ok)} {fixable} of {len(res.findings)} can be fixed automatically: "
                   f"run {st.bold('paddock fix')} to see the diff first")
    for n in res.notes:
        if n.startswith("SAST engine"):
            continue
        out.append(f"  {st.yellow('!')} {n}")
    out.append("")
    return "\n".join(out)


def summary_line(res: ScanResult, st: Style) -> str:
    c = res.counts()
    parts = [f"{st.sev(s, f'{c[s]} {s}')}" if c[s] else st.dim(f"0 {s}")
             for s in reversed(SEVERITIES) if s != "info" or c[s]]
    total = len(res.findings)
    return f"{st.bold(str(total))} finding{'s' if total != 1 else ''}:  " + "  ".join(parts)


def sort_key(f: Finding):
    return (-rank(f.severity), f.file, f.line or 0)
