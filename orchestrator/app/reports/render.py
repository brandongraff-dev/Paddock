"""HTML (Jinja2) and PDF (WeasyPrint) rendering for reports.

The HTML is self-contained -- fonts are embedded as data: URIs and charts are
inline SVG -- so a forwarded file renders the same in any mail client or
browser, offline. The PDF is the same HTML laid out by WeasyPrint with the
print stylesheet (A4 by default, `REPORTS_PAGE_SIZE` to change).

WeasyPrint needs Pango at the OS level. It is imported lazily so the API (and
every other format) keeps working where it is missing; `format=pdf` then
answers 501 with the reason.
"""

from __future__ import annotations

import base64
import functools
import io
from datetime import datetime
from pathlib import Path
from typing import Any

from jinja2 import Environment, FileSystemLoader, select_autoescape

from . import svg
from .metrics import fmt_hours
from .models import ReportData

HERE = Path(__file__).resolve().parent
TEMPLATES = HERE / "templates"
FONTS = HERE / "fonts"

_FONT_FACES = (
    ("Newsreader", "newsreader-latin-wght-normal.woff2", "200 800", "normal"),
    ("Newsreader", "newsreader-latin-wght-italic.woff2", "200 800", "italic"),
    ("Inter", "inter-latin-400-normal.woff2", "400", "normal"),
    ("Inter", "inter-latin-500-normal.woff2", "500", "normal"),
    ("Inter", "inter-latin-600-normal.woff2", "600", "normal"),
    ("JetBrains Mono", "jetbrains-mono-latin-400-normal.woff2", "400", "normal"),
)


class PdfUnavailable(RuntimeError):
    """WeasyPrint (or its system libraries) is not installed."""


@functools.lru_cache(maxsize=1)
def font_css() -> str:
    out = []
    for family, fname, weight, style in _FONT_FACES:
        p = FONTS / fname
        if not p.exists():
            continue
        b64 = base64.b64encode(p.read_bytes()).decode("ascii")
        out.append(
            f"@font-face{{font-family:'{family}';font-style:{style};font-weight:{weight};"
            f"font-display:swap;src:url(data:font/woff2;base64,{b64}) format('woff2');}}"
        )
    return "\n".join(out)


def _num(v: Any) -> str:
    if v is None:
        return "—"
    if isinstance(v, float) and not v.is_integer():
        return f"{v:,.1f}"
    return f"{int(v):,}"


def _pct(v: Any, digits: int = 0) -> str:
    return "—" if v is None else f"{v:.{digits}f}%"


def _date(v: datetime | None, fmt: str = "%-d %b %Y") -> str:
    return "—" if v is None else v.strftime(fmt)


def _signed(v: int | float | None) -> str:
    if v is None:
        return "—"
    return f"+{v:,}" if v > 0 else f"−{abs(v):,}" if v < 0 else "±0"


_KIND_LABEL = {
    "ipv4": "IPv4",
    "ipv6": "IPv6",
    "iot_device": "IoT device",
    "ot_device": "OT device",
    "cloud_account": "Cloud account",
    "cloud_resource": "Cloud resource",
    "network_segment": "Network segment",
}


def _title(s: str | None) -> str:
    s = s or ""
    return _KIND_LABEL.get(s) or s.replace("_", " ").capitalize()


@functools.lru_cache(maxsize=1)
def env() -> Environment:
    e = Environment(
        loader=FileSystemLoader(str(TEMPLATES)),
        autoescape=select_autoescape(["html", "j2"]),
        trim_blocks=True,
        lstrip_blocks=True,
    )
    e.filters.update(
        num=_num,
        pct=_pct,
        date=_date,
        hours=fmt_hours,
        signed=_signed,
        title_=_title,
    )
    e.globals.update(svg=svg, SEV=svg.SEV, STATUS=svg.STATUS)
    return e


def render_template(name: str, **ctx: Any) -> str:
    from .config import report_settings

    ctx.setdefault("page_size", getattr(report_settings, "page_size", "A4"))
    return env().get_template(name).render(font_css=font_css(), **ctx)


def html_to_pdf(html: str) -> bytes:
    try:
        from weasyprint import HTML  # type: ignore
    except Exception as exc:  # noqa: BLE001 -- ImportError or missing Pango (OSError)
        raise PdfUnavailable(
            "PDF rendering needs WeasyPrint and Pango (pip install weasyprint; "
            "apt-get install libpango-1.0-0 libpangoft2-1.0-0)"
        ) from exc
    buf = io.BytesIO()
    HTML(string=html, base_url=str(TEMPLATES)).write_pdf(buf)
    return buf.getvalue()


# --------------------------------------------------------------------------- #
# Documents
# --------------------------------------------------------------------------- #


def _css_safe(s: str) -> str:
    """Text placed inside a CSS string (the @page footer)."""
    return "".join(ch for ch in s if ch not in '"\\<>{}\n\r')[:80]


def footer_text(org_name: str, clearance: str) -> str:
    return _css_safe(f"{org_name} · up to {clearance}")


def render_executive_html(r: ReportData) -> str:
    team_rows = [(m.key, m.median_hours, fmt_hours(m.median_hours)) for m in r.mttr.by_team[:6]]
    total = r.coverage.assets_total
    fresh = sum(k.seen_7d for k in r.coverage.by_kind)
    return render_template(
        "executive.html.j2",
        r=r,
        trend_points=[(p.at, p.value) for p in r.exposure.points],
        team_rows=team_rows,
        fresh_pct=(100.0 * fresh / total) if total else None,
        footer_left=footer_text(r.org_name, r.clearance),
    )
