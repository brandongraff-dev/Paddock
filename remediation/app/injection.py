"""Prompt-injection / payload scanner (THREAT-MODEL LAYER 5).

A finding's fields (title, description, evidence, package name, CVE text) are
ATTACKER-INFLUENCEABLE: they can come from scanned content, a crafted package
name, or a malicious repo. This module treats all of that as HOSTILE DATA and
scans it — plus any generated PR title/body — for:

  * instruction-override patterns ("ignore previous instructions", "you are
    now", "disregard the above", "new system prompt", DAN/jailbreak)
  * action / exfiltration verbs ("run", "execute", "exfiltrate", "add a
    backdoor", "reverse shell", "curl ... | bash", "rm -rf", "POST to http")
  * exploit / payload tokens (<script>, eval(, __import__, /bin/sh, ${...},
    {{...}}, powershell, cmd.exe)
  * base64-looking blobs (long opaque [A-Za-z0-9+/]{40,} runs)
  * hidden / invisible unicode (zero-width, bidi overrides, control chars)
  * URLs in odd places (raw-IP URLs, userinfo@host, non-reference URLs)

Results are structured so the pipeline can record them in
``remediations.injection_checks`` and REFUSE to open a PR when the scanned text
would carry injected instructions.

Nothing here executes, fetches, or interprets the scanned text. Two small
helpers — ``sanitize`` and ``wrap_as_data`` — support LAYER 1 (untrusted-data
isolation) by stripping control sequences and fencing untrusted text before it
is ever shown to an LLM.
"""
from __future__ import annotations

import re
import unicodedata
from dataclasses import dataclass, field
from typing import Any, Iterable

# --------------------------------------------------------------------------- #
# Invisible / control unicode. Zero-width + bidi overrides are a classic way to
# smuggle instructions past a human reviewer while the model still reads them.
# --------------------------------------------------------------------------- #
_INVISIBLE_CHARS = (
    "​‌‍⁠﻿"           # zero-width space/joiner/no-break
    "‪‫‬‭‮"           # bidi embeddings / overrides
    "⁦⁧⁨⁩"                 # bidi isolates
    "­"                                    # soft hyphen
    "᠎‎‏"                        # mongolian vowel sep / LRM / RLM
)
_INVISIBLE_RE = re.compile("[" + re.escape(_INVISIBLE_CHARS) + "]")
# Control chars except tab/newline/carriage-return.
_CONTROL_RE = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]")


@dataclass
class Hit:
    category: str
    pattern: str
    sample: str
    blocking: bool
    field: str | None = None

    def as_dict(self) -> dict[str, Any]:
        return {
            "category": self.category,
            "pattern": self.pattern,
            "sample": self.sample,
            "blocking": self.blocking,
            "field": self.field,
        }


# Each rule: (category, compiled regex, blocking?). A blocking hit means the
# text carries something that must NOT be acted on / must not reach a PR.
_RULES: list[tuple[str, re.Pattern[str], bool]] = [
    # --- instruction override ------------------------------------------------
    ("instruction_override",
     re.compile(r"\bignore\s+(all\s+|any\s+)?(previous|prior|above|earlier|the\s+above)\b", re.I), True),
    ("instruction_override",
     re.compile(r"\b(disregard|forget|override)\s+(all\s+|any\s+|the\s+)?(previous|prior|above|instructions?|rules?|system)\b", re.I), True),
    ("instruction_override",
     re.compile(r"\byou\s+are\s+now\b|\bact\s+as\b|\bpretend\s+to\s+be\b|\bnew\s+(system\s+)?(prompt|instructions?|rules?)\b", re.I), True),
    ("instruction_override",
     re.compile(r"\b(system\s*prompt|developer\s*message|assistant\s*:|<\s*system\s*>)\b", re.I), True),
    ("instruction_override",
     re.compile(r"\b(DAN|do\s+anything\s+now|jailbreak|without\s+restrictions?)\b", re.I), True),
    # --- action / exfiltration ----------------------------------------------
    ("action_exfil",
     re.compile(r"\b(add|insert|inject|plant|leave)\s+(a\s+)?(backdoor|web\s*shell|webshell|rootkit|implant|trojan|malware)\b", re.I), True),
    ("action_exfil",
     re.compile(r"\b(reverse|bind)\s+shell\b|\bnc\s+-e\b|\b/dev/tcp/\b", re.I), True),
    ("action_exfil",
     re.compile(r"\b(exfiltrate|exfil|leak|steal|dump)\b.{0,40}\b(secret|token|key|credential|password|env)\b", re.I), True),
    ("action_exfil",
     re.compile(r"\b(curl|wget|fetch)\b[^\n]{0,80}\|\s*(bash|sh|zsh|python)\b", re.I), True),
    ("action_exfil",
     re.compile(r"\brm\s+-rf\b|\bchmod\s+\+s\b|\bchmod\s+777\b|\bmkfifo\b", re.I), True),
    ("action_exfil",
     re.compile(r"\b(run|execute|eval)\s+(the\s+)?(following|this|command|code|script|payload)\b", re.I), True),
    ("action_exfil",
     re.compile(r"\b(POST|GET|send|upload|beacon|callback)\b[^\n]{0,40}https?://", re.I), True),
    # --- exploit / payload tokens -------------------------------------------
    ("exploit_token", re.compile(r"<\s*script\b|</\s*script\s*>|javascript:", re.I), True),
    ("exploit_token", re.compile(r"\beval\s*\(|\bexec\s*\(|\b__import__\b|\bos\.system\b|\bsubprocess\b", re.I), True),
    ("exploit_token", re.compile(r"child_process|require\(\s*['\"]child_process", re.I), True),
    ("exploit_token", re.compile(r"/bin/(ba)?sh\b|\bpowershell\b|\bcmd\.exe\b|\bbash\s+-i\b", re.I), True),
    ("exploit_token", re.compile(r"\$\{[^}]{0,80}\}|\{\{[^}]{0,80}\}\}|\$\([^)]{0,80}\)", re.I), True),
    ("exploit_token", re.compile(r"\.\./\.\./|\betc/passwd\b|\bfile://", re.I), True),
]

# Base64-looking opaque blob: a long unbroken run of base64 alphabet. Catches
# encoded payloads smuggled into evidence/description.
_BASE64_RE = re.compile(r"[A-Za-z0-9+/]{40,}={0,2}")
# A word that is suspiciously long and all-hex (encoded shellcode / blobs).
_HEXBLOB_RE = re.compile(r"\b(?:0x)?[0-9a-fA-F]{48,}\b")
# URL with a raw IP host or userinfo — "URL in an odd place".
_ODD_URL_RE = re.compile(
    r"https?://(?:[^\s/@]+@)?(?:\d{1,3}(?:\.\d{1,3}){3})(?:[:/]\S*)?", re.I)
_ANY_URL_RE = re.compile(r"https?://\S+", re.I)


def sanitize(text: str) -> str:
    """Strip invisible/control unicode and normalize (LAYER 1 helper).

    Removes zero-width characters, bidi overrides and control bytes that would
    let an attacker hide instructions from a human reviewer while a model still
    reads them. NFKC-normalizes so look-alike glyphs collapse. The result is
    what we display and (fenced) what we hand to an LLM — we never send the raw
    bytes.
    """
    if not text:
        return ""
    text = unicodedata.normalize("NFKC", text)
    text = _INVISIBLE_RE.sub("", text)
    text = _CONTROL_RE.sub("", text)
    return text


def wrap_as_data(label: str, text: str) -> str:
    """Fence untrusted ``text`` inside a clearly-delimited, unique data block
    (LAYER 1). The delimiter is randomized-ish per call via the label so the
    text cannot close the fence and escape into the instruction portion.
    """
    clean = sanitize(text or "")
    # Neutralize any attempt to forge our fence.
    marker = f"<<<{label.upper()}_DATA>>>"
    end = f"<<<END_{label.upper()}_DATA>>>"
    clean = clean.replace(marker, "").replace(end, "")
    return f"{marker}\n{clean}\n{end}"


def _sample(s: str, span: tuple[int, int], width: int = 48) -> str:
    start, end = span
    lo = max(0, start - 8)
    hi = min(len(s), end + 8)
    frag = s[lo:hi].replace("\n", "\\n")
    return (frag[: width] + "…") if len(frag) > width else frag


def _scan_one(name: str, raw: str) -> list[Hit]:
    hits: list[Hit] = []
    if not raw:
        return hits

    # Hidden unicode is checked on the RAW text (before sanitize strips it).
    inv = _INVISIBLE_RE.findall(raw)
    if inv:
        names = sorted({unicodedata.name(c, f"U+{ord(c):04X}") for c in inv})
        hits.append(Hit("hidden_unicode", "invisible/bidi chars",
                        ", ".join(names)[:48], True, name))
    ctl = _CONTROL_RE.findall(raw)
    if ctl:
        hits.append(Hit("hidden_unicode", "control chars",
                        f"{len(ctl)} control byte(s)", True, name))

    # Everything else runs on the sanitized text so an attacker can't split a
    # keyword with a zero-width char to dodge the regexes.
    text = sanitize(raw)

    for category, rx, blocking in _RULES:
        m = rx.search(text)
        if m:
            hits.append(Hit(category, rx.pattern[:60], _sample(text, m.span()),
                            blocking, name))

    for m in _BASE64_RE.finditer(text):
        # Ignore if it is clearly a whitespace-free hash/digest reference line.
        hits.append(Hit("base64_blob", "long base64-ish run",
                        _sample(text, m.span()), True, name))
        break
    for m in _HEXBLOB_RE.finditer(text):
        hits.append(Hit("hex_blob", "long hex run", _sample(text, m.span()), True, name))
        break

    # URLs: a raw-IP / userinfo URL is a blocking "odd place"; an ordinary URL
    # in a free-text field is a non-blocking note (references legitimately have
    # URLs, so we don't scan those).
    odd = _ODD_URL_RE.search(text)
    if odd:
        hits.append(Hit("odd_url", "raw-ip/userinfo url", _sample(text, odd.span()), True, name))
    else:
        url = _ANY_URL_RE.search(text)
        if url:
            hits.append(Hit("url", "url in text", _sample(text, url.span()), False, name))

    return hits


def scan_fields(fields: dict[str, Any]) -> dict[str, Any]:
    """Scan a mapping of {field_name: text}. Non-string values are stringified.

    Returns the ``injection_checks`` record:
      {scanned:[...], hits:[{...}], categories:[...], flagged:bool, blocked:bool}
    ``flagged`` is True if ANY hit (incl. non-blocking notes); ``blocked`` is
    True if any BLOCKING hit — that is the signal to refuse to act / open a PR.
    """
    all_hits: list[Hit] = []
    scanned: list[str] = []
    for key, value in fields.items():
        if value is None:
            continue
        raw = value if isinstance(value, str) else _stringify(value)
        scanned.append(key)
        all_hits.extend(_scan_one(key, raw))

    blocking = [h for h in all_hits if h.blocking]
    categories = sorted({h.category for h in all_hits})
    return {
        "scanned": scanned,
        "hits": [h.as_dict() for h in all_hits],
        "categories": categories,
        "flagged": bool(all_hits),
        "blocked": bool(blocking),
        "summary": _summarize(all_hits),
    }


def _summarize(hits: list[Hit]) -> str:
    if not hits:
        return "no injection detected"
    blocking = [h for h in hits if h.blocking]
    if blocking:
        cats = sorted({h.category for h in blocking})
        return "blocked: " + ", ".join(cats)
    return "note: " + ", ".join(sorted({h.category for h in hits}))


def _stringify(value: Any) -> str:
    """Flatten arbitrary JSON-ish evidence into scannable text."""
    import json

    try:
        return json.dumps(value, default=str, ensure_ascii=False)
    except Exception:  # pragma: no cover - defensive
        return str(value)


def finding_fields(finding: dict[str, Any]) -> dict[str, Any]:
    """The attacker-influenceable fields of a finding, for scanning. Note we do
    NOT scan ``references`` (legitimately a list of URLs)."""
    asset = finding.get("asset") or {}
    return {
        "title": finding.get("title"),
        "description": finding.get("description"),
        "impact": finding.get("impact"),
        "remediation": finding.get("remediation"),
        "evidence": finding.get("evidence"),
        "metadata": finding.get("metadata"),
        "asset_value": asset.get("value"),
    }


def gather_scannable(
    finding: dict[str, Any] | None = None,
    *,
    pr_title: str | None = None,
    pr_body: str | None = None,
    extra: Iterable[tuple[str, Any]] = (),
) -> dict[str, Any]:
    fields: dict[str, Any] = {}
    if finding is not None:
        fields.update(finding_fields(finding))
    if pr_title is not None:
        fields["pr_title"] = pr_title
    if pr_body is not None:
        fields["pr_body"] = pr_body
    for key, value in extra:
        fields[key] = value
    return fields
