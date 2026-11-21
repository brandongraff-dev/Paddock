"""Inline SVG charts for printed reports (no JS, no network, WeasyPrint-safe).

Print palette = the "albumen print" light theme of the Daguerreotype system:
cream paper, warm ink, patina-blue accent. The severity ramp is the dashboard
ramp re-stepped for a light surface (validated: one hue, monotone lightness,
light end >= 2:1 on the paper). Marks follow the dataviz rules: 2px lines, an
area wash at ~10%, hairline recessive grid, rounded bar ends, 2px paper gaps
between touching segments, text always in ink tokens, never series colour.
"""

from __future__ import annotations

import hashlib
import math
from datetime import datetime
from html import escape
from typing import Iterable, Sequence

from markupsafe import Markup

from .brand import HORSE_MARK_H, HORSE_MARK_PATH, HORSE_MARK_W

PAPER = "#fbf8f2"
PAPER_2 = "#f4efe6"
INK = "#1b1712"
INK_2 = "#4a4239"
INK_3 = "#7a7064"
RULE = "#e4dccd"
GRID = "#ece5d8"
ACCENT = "#3f6a85"

SEV = {
    "critical": "#8f3226",
    "high": "#b55837",
    "medium": "#c97a4f",
    "low": "#d49a72",
    "info": "#b3aa9e",
}
STATUS = {
    "satisfied": "#4f7d4a",
    "partial": "#b8862f",
    "gap": "#a8382c",
    "requires_attestation": "#b3aa9e",
}

SANS = "Inter, 'Helvetica Neue', Arial, sans-serif"
MONO = "'JetBrains Mono', 'DejaVu Sans Mono', monospace"


def _n(v: float) -> str:
    return f"{v:.1f}".rstrip("0").rstrip(".")


def _txt(
    x: float,
    y: float,
    s: str,
    *,
    size: float = 8.5,
    fill: str = INK_3,
    anchor: str = "start",
    weight: int = 400,
    family: str = MONO,
) -> str:
    return (
        f'<text x="{_n(x)}" y="{_n(y)}" font-family="{family}" font-size="{size}" '
        f'font-weight="{weight}" fill="{fill}" text-anchor="{anchor}">{escape(s)}</text>'
    )


def horse_mark(size: float = 28, color: str = INK, ring: bool = True) -> Markup:
    """The brand mark (same geometry as dashboard/src/brand/HorseMark.tsx)."""
    s = 26 / HORSE_MARK_W
    tx = (40 - HORSE_MARK_W * s) / 2
    ty = (40 - HORSE_MARK_H * s) / 2 + 0.6
    ring_svg = (
        f'<circle cx="20" cy="20" r="18.6" fill="none" stroke="{color}" stroke-width="1.6"/>'
        if ring
        else ""
    )
    return Markup(
        f'<svg class="mark" width="{size}" height="{size}" viewBox="0 0 40 40" role="img" aria-label="Paddock">'
        f"{ring_svg}"
        f'<path d="{HORSE_MARK_PATH}" transform="translate({_n(tx)} {_n(ty)}) scale({s:.4f})" '
        f'fill="{color}" shape-rendering="crispEdges"/></svg>'
    )


def _nice_step(v: float) -> float:
    """A round step so that three steps cover v (1, 2, 2.5, 5 x 10^k)."""
    raw = max(v, 1e-9) / 3
    mag = 10 ** math.floor(math.log10(raw))
    for m in (1, 2, 2.5, 5, 10):
        if m * mag >= raw:
            return max(1.0, m * mag)
    return max(1.0, 10 * mag)


def trend(
    points: Sequence[tuple[datetime, float]],
    *,
    width: float = 520,
    height: float = 150,
    color: str = ACCENT,
    label: str = "Exposure index",
) -> Markup:
    """Single-series line + wash with a start and end label and a hairline grid."""
    if not points:
        return Markup("")
    ml, mr, mt, mb = 34, 44, 10, 20
    iw, ih = width - ml - mr, height - mt - mb
    vals = [p[1] for p in points]
    step = _nice_step(max(vals) * 1.05 if max(vals) else 3)
    ticks = 3
    while step * ticks < max(vals):
        ticks += 1
    vmax = step * ticks
    n = len(points)

    def x(i: int) -> float:
        return ml + (iw * i / (n - 1) if n > 1 else iw / 2)

    def y(v: float) -> float:
        return mt + ih - ih * (v / vmax)

    parts = [
        f'<svg class="chart" width="{_n(width)}" height="{_n(height)}" viewBox="0 0 {_n(width)} {_n(height)}" '
        f'role="img" aria-label="{escape(label)} over the period">'
    ]
    for k in range(ticks + 1):
        gv = step * k
        gy = y(gv)
        parts.append(
            f'<line x1="{ml}" x2="{_n(ml + iw)}" y1="{_n(gy)}" y2="{_n(gy)}" stroke="{GRID}" stroke-width="1"/>'
        )
        parts.append(_txt(ml - 6, gy + 3, f"{gv:,.0f}", anchor="end"))
    line = " ".join(f"{'M' if i == 0 else 'L'}{_n(x(i))},{_n(y(v))}" for i, v in enumerate(vals))
    area = line + f" L{_n(x(n - 1))},{_n(y(0))} L{_n(x(0))},{_n(y(0))} Z"
    parts.append(f'<path d="{area}" fill="{color}" fill-opacity="0.10" stroke="none"/>')
    parts.append(
        f'<path d="{line}" fill="none" stroke="{color}" stroke-width="2" stroke-linejoin="round" stroke-linecap="round"/>'
    )
    # end markers: >= 8px, 2px paper ring
    for i in (0, n - 1):
        parts.append(
            f'<circle cx="{_n(x(i))}" cy="{_n(y(vals[i]))}" r="4" fill="{color}" stroke="{PAPER}" stroke-width="2"/>'
        )
    parts.append(
        _txt(x(n - 1) + 8, y(vals[-1]) + 3.5, f"{vals[-1]:,.0f}", size=10, fill=INK, weight=500)
    )
    # x labels: first, middle, last
    idx = sorted({0, (n - 1) // 2, n - 1})
    for i in idx:
        anchor = "start" if i == 0 else "end" if i == n - 1 else "middle"
        parts.append(_txt(x(i), height - 5, points[i][0].strftime("%-d %b"), anchor=anchor))
    parts.append("</svg>")
    return Markup("".join(parts))


def hbars(
    rows: Iterable[tuple[str, float, str]],
    *,
    width: float = 250,
    row_h: float = 20,
    label_w: float = 92,
    value_w: float = 46,
    color: str = INK_2,
    fmt=None,
    aria: str = "Bar chart",
) -> Markup:
    """Ranked horizontal bars. rows = (label, value, display_value)."""
    rows = list(rows)
    if not rows:
        return Markup("")
    vmax = max(r[1] for r in rows) or 1
    bw = width - label_w - value_w
    bar_h = 7
    h = row_h * len(rows)
    parts = [
        f'<svg class="chart" width="{_n(width)}" height="{_n(h)}" viewBox="0 0 {_n(width)} {_n(h)}" role="img" aria-label="{escape(aria)}">'
    ]
    for i, (lab, v, disp) in enumerate(rows):
        cy = i * row_h + row_h / 2
        lab_s = lab if len(lab) <= 16 else lab[:15] + "…"
        parts.append(_txt(0, cy + 3, lab_s, size=8.5, fill=INK_2, family=SANS))
        parts.append(
            f'<rect x="{_n(label_w)}" y="{_n(cy - bar_h / 2)}" width="{_n(bw)}" height="{bar_h}" rx="3.5" fill="{GRID}"/>'
        )
        w = max(3.0, bw * (v / vmax)) if v > 0 else 0
        if w:
            parts.append(
                f'<rect x="{_n(label_w)}" y="{_n(cy - bar_h / 2)}" width="{_n(w)}" height="{bar_h}" rx="3.5" fill="{color}"/>'
            )
        parts.append(_txt(width, cy + 3, disp, size=8.5, fill=INK, anchor="end"))
    parts.append("</svg>")
    return Markup("".join(parts))


def stacked(
    segments: Sequence[tuple[str, float, str]],
    *,
    width: float = 250,
    height: float = 10,
    aria: str = "Composition",
) -> Markup:
    """A 100% strip of (key, value, colour) with 2px paper gaps between segments."""
    total = sum(s[1] for s in segments)
    parts = [
        f'<svg class="chart strip" width="{_n(width)}" height="{_n(height)}" viewBox="0 0 {_n(width)} {_n(height)}" role="img" aria-label="{escape(aria)}">'
    ]
    if total <= 0:
        parts.append(
            f'<rect x="0" y="0" width="{_n(width)}" height="{_n(height)}" rx="{_n(height / 2)}" fill="{GRID}"/>'
        )
    else:
        live = [s for s in segments if s[1] > 0]
        gap = 2.0
        avail = width - gap * (len(live) - 1)
        x = 0.0
        for i, (_k, v, c) in enumerate(live):
            w = max(2.0, avail * v / total)
            if i == len(live) - 1:
                w = width - x
            parts.append(
                f'<rect x="{_n(x)}" y="0" width="{_n(w)}" height="{_n(height)}" fill="{c}"/>'
            )
            x += w + gap
        # round the outer ends only
        cid = "c" + hashlib.md5(repr((segments, width, height)).encode()).hexdigest()[:10]
        parts.insert(
            1,
            f'<clipPath id="{cid}"><rect width="{_n(width)}" height="{_n(height)}" rx="{_n(height / 2)}"/></clipPath><g clip-path="url(#{cid})">',
        )
        parts.append("</g>")
    parts.append("</svg>")
    return Markup("".join(parts))


def sev_strip(counts: dict[str, int], width: float = 250) -> Markup:
    order = ("critical", "high", "medium", "low", "info")
    return stacked(
        [(k, counts.get(k, 0), SEV[k]) for k in order],
        width=width,
        aria="Open findings by severity",
    )


def status_strip(counts: dict[str, int], width: float = 250, height: float = 8) -> Markup:
    order = ("satisfied", "partial", "gap", "requires_attestation")
    return stacked(
        [(k, counts.get(k, 0), STATUS[k]) for k in order],
        width=width,
        height=height,
        aria="Controls by status",
    )
