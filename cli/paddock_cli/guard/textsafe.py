# SPDX-License-Identifier: AGPL-3.0-or-later
"""Text safety for everything that reaches a user or an agent (contract 3.11 H5, 4.0.4, 8.4).

Repo-derived text is DATA. ``clean`` removes every character class that can hide or reorder
text, ``ascii_escape`` makes the remaining non-ASCII visible, ``cap`` bounds length and
``redact`` produces the only form in which a secret may ever appear (D10, H6). There is no
function here that hashes a secret value, on purpose.
"""
from __future__ import annotations

import re
import unicodedata

_FORBIDDEN_CATEGORIES = frozenset({"Cc", "Cf", "Cs", "Co", "Cn"})

# Explicit list of characters that survive the category filter but still hide or reorder text
# (contract 3.11 H5): combining grapheme joiner, Hangul fillers, Khmer vowel inherent, line and
# paragraph separators, Braille blank, Hangul filler and halfwidth filler, variation selectors
# and variation selector supplement.
_EXPLICIT = frozenset(
    [0x034F, 0x115F, 0x1160, 0x17B4, 0x17B5, 0x2028, 0x2029, 0x2800, 0x3164, 0xFFA0]
    + list(range(0xFE00, 0xFE10))
    + list(range(0xE0100, 0xE01F0))
)

# ANSI: CSI (ESC [ ... final), OSC (ESC ] ... BEL or ST), other two-byte ESC sequences and the
# single-byte C1 CSI / OSC introducers.
_ANSI = re.compile(
    r"(?:\x1b\[[0-?]*[ -/]*[@-~])"
    r"|(?:\x1b\][^\x07\x1b]*(?:\x07|\x1b\\)?)"
    r"|(?:\x1b[@-Z\\-_])"
    r"|(?:\x9b[0-?]*[ -/]*[@-~])"
    r"|(?:\x9d[^\x07\x9c]*(?:\x07|\x9c)?)"
)
_NEEDS_WORK = re.compile(r"[^\x20-\x7e]")
_WS_CONTROLS = {"\t", "\n", "\r", "\x0b", "\x0c"}
_CAT_CACHE: dict[str, str | None] = {}


def _decide(ch: str) -> str | None:
    """Replacement for one non-printable-ASCII character: '' remove, ' ' space, None keep."""
    hit = _CAT_CACHE.get(ch)
    if hit is not None or ch in _CAT_CACHE:
        return hit
    cp = ord(ch)
    cat = unicodedata.category(ch)
    if ch in _WS_CONTROLS:
        out: str | None = " "
    elif cat == "Zs":
        out = " "
    elif cat in _FORBIDDEN_CATEGORIES or cp in _EXPLICIT:
        out = ""
    else:
        out = None
    if len(_CAT_CACHE) < 4096:
        _CAT_CACHE[ch] = out
    return out


def clean(text: object, *, keep_newlines: bool = False) -> str:
    """Remove ANSI sequences and categories Cc Cf Cs Co Cn plus the explicit H5 list.

    Every ``Zs`` space (and C0 whitespace controls) becomes U+0020 so words are not glued
    together. With ``keep_newlines`` a plain ``\\n`` survives (multi-line templates).
    """
    s = "" if text is None else str(text)
    if "\x1b" in s or "\x9b" in s or "\x9d" in s:
        s = _ANSI.sub("", s)
    if not _NEEDS_WORK.search(s):
        return s
    out: list[str] = []
    for ch in s:
        if " " <= ch <= "~":
            out.append(ch)
            continue
        if keep_newlines and ch == "\n":
            out.append(ch)
            continue
        rep = _decide(ch)
        out.append(ch if rep is None else rep)
    return "".join(out)


def ascii_escape(text: object) -> str:
    """Rewrite every non-ASCII character as a visible ``\\uXXXX`` (``\\UXXXXXXXX`` above BMP)."""
    s = "" if text is None else str(text)
    if s.isascii():
        return s
    out: list[str] = []
    for ch in s:
        cp = ord(ch)
        if cp < 128:
            out.append(ch)
        elif cp <= 0xFFFF:
            out.append("\\u%04x" % cp)
        else:
            out.append("\\U%08x" % cp)
    return "".join(out)


def _cap_impl(text: str, limit: int) -> str:
    if limit < 0:
        limit = 0
    if len(text) <= limit:
        return text
    if limit <= 3:
        return text[:limit]
    return text[: limit - 3] + "..."


def cap(text: str, limit: int) -> str:
    """Truncate to at most ``limit`` characters, ending with an ASCII ellipsis when cut."""
    return _cap_impl(text, limit)


def collapse_ws(text: str) -> str:
    return " ".join(text.split())


def safe_text(text: object, *, cap: int = 200, escape: bool = True) -> str:  # noqa: A002
    """Clean, escape (agent channels), collapse whitespace and cap, in that order (8.4 item 1)."""
    s = clean(text)
    if escape:
        s = ascii_escape(s)
    return _cap_impl(collapse_ws(s), cap)


# Public family prefixes that may be shown in evidence next to ``****`` (contract 3.4, 4.0.4).
PUBLIC_PREFIXES: frozenset[str] = frozenset({
    "AKIA", "ASIA", "ghp_", "gho_", "ghu_", "ghs_", "ghr_", "github_pat_", "glpat-",
    "xoxb-", "xoxa-", "xoxp-", "xoxr-", "xoxs-", "npm_", "SG.", "sk_live_", "rk_live_",
    "whsec_", "sk-ant-", "sk-proj-", "sk-svcacct-", "sk-admin-", "sk-", "hf_", "gsk_",
    "sb_secret_", "eyJ", "-----BEGIN",
})


def redact(value: object, public_prefix: str = "") -> str:
    """The only form in which a secret appears: optional declared public prefix, ``****``, length.

    ``public_prefix`` is honoured only when it is in ``PUBLIC_PREFIXES`` and the value really
    starts with it; otherwise no character of the value is returned (D10, 3.11 H6).
    """
    v = "" if value is None else str(value)
    prefix = ""
    if public_prefix and public_prefix in PUBLIC_PREFIXES and v.startswith(public_prefix):
        prefix = public_prefix
    return "%s****[%d]" % (prefix, len(v))


def bracket_depth(text: str, limit: int = 100) -> int:
    """Deepest ``[``/``{`` nesting in JSON-like text (string-aware); stops counting past ``limit``."""
    depth = best = 0
    in_str = esc = False
    for ch in text:
        if in_str:
            if esc:
                esc = False
            elif ch == "\\":
                esc = True
            elif ch == '"':
                in_str = False
        elif ch == '"':
            in_str = True
        elif ch in "[{":
            depth += 1
            if depth > best:
                best = depth
                if best > limit:
                    return best
        elif ch in "]}" and depth:
            depth -= 1
    return best


def loads_bounded(text: str, max_depth: int = 100) -> object:
    """``json.loads`` after refusing text nested deeper than ``max_depth`` (3.11 H4); raises ValueError."""
    import json

    # fewer open brackets than the limit cannot nest deeper than it: skip the scan
    if text.count("[") + text.count("{") > max_depth and bracket_depth(text, max_depth) > max_depth:
        raise ValueError("JSON nested too deeply")
    try:
        return json.loads(text)
    except (RecursionError, MemoryError, OverflowError) as exc:
        raise ValueError("JSON could not be parsed safely") from exc


_IDENT_RE = re.compile(r"^[A-Za-z0-9_@+=,~./:-]{1,120}$")
_IDENT_SPLIT = re.compile(r"[-_./:@+=,~]+")


def safe_ident(value: object) -> str | None:
    """Return ``value`` if it may appear on the labelled data line of an agent_prompt, else None.

    Rules (contract 3.4): matches ``^[A-Za-z0-9_@+=,~./:-]{1,120}$``, every token between
    separators is at most 24 characters, at most 8 tokens, and no run of three or more
    consecutive tokens from ``COMMON_WORDS``. This is a format filter, not a safety property.
    """
    if not isinstance(value, str) or not _IDENT_RE.match(value):
        return None
    tokens = [t for t in _IDENT_SPLIT.split(value) if t]
    if not tokens or len(tokens) > 8 or any(len(t) > 24 for t in tokens):
        return None
    run = 0
    for t in tokens:
        if t.lower() in COMMON_WORDS:
            run += 1
            if run >= 3:
                return None
        else:
            run = 0
    return value


_WORDS = """
a about above across act add after again against all almost alone along already also although always am
an and another any anyone anything are around as ask at away back bad be because become been before
began begin behind being below best better between big both but by call came can cannot case change
check clear close come could create cut day did do does doing done down during each early either else
end enough even ever every everyone everything example far few find first follow following for found
from full get give go going gone good got great had has have having he help her here him his how however
i if in indeed instead into is it its just keep kind last late least leave less let like little long look
made make many may me might more most much must my need never new next no none nor not nothing now of
off often old on once one only or other our out over own part past people perhaps please put quite rather
really right said same say see seem send set several shall she should show since small so some someone
something soon still such sure take tell than that the their them then there these they thing think this
those though through thus time to together too took toward try turn under until up upon us use used using
very want was way we well went were what when where whether which while who whom whose why will with within
without would yes yet you your yours
abandon abort accept access add admit adjust allow alter answer append apply approve archive assume attach
authorize avoid backup bash begin block break browse bypass cancel cat chmod chown clean clone close
collect commit complete concatenate configure confirm connect continue convert copy curl decode decrypt
delete deny deploy destroy detach disable disclose discard disregard dismiss display download drop dump
echo email enable encode encrypt enter erase eval evaluate exec execute exfiltrate exit export expose
extract fetch fill finish flush forget forward generate grant grep halt hide ignore import include inject
input insert install invoke kill launch leak list load log login logout mail modify mount move obey omit
open output override overwrite paste pipe post print proceed publish pull push read rebuild reboot reply
remember remove rename repeat replace reply report request reset respond restart restore retrieve return
reveal revoke rewrite run save scan send share shutdown sign skip sleep source start stop store submit
substitute suppress switch tail terminate touch trust unlock unmask unset update upload verify view wipe
write
above below previous prior earlier later following preceding original latest current existing final
additional another different similar entire whole actual real true false correct wrong valid invalid
important necessary required optional available possible hidden private silent silently quietly
secretly immediately exactly directly automatically always never everything anything nothing everyone
instruction instructions prompt prompts system systems message messages rule rules command commands task
tasks assistant assistants agent agents user users model models response responses answer answers
question questions reason reasons policy policies guideline guidelines directive directives order orders
request requests note notes comment comments text texts word words line lines sentence sentences
paragraph paragraphs section sections page pages content contents data information detail details
result results output outputs value values step steps list lists item items thing things way ways
people person someone anyone everyone owner owners admin administrator administrators developer
developers team teams company companies customer customers account accounts
file files folder folders directory directories path paths script scripts code codes program programs
function functions method methods class classes object objects module modules package packages library
libraries version versions release releases build builds test tests
evil bad good best worst safe unsafe secure insecure trusted untrusted malicious harmful dangerous
sh md txt
""".split()

COMMON_WORDS: frozenset[str] = frozenset(w.lower() for w in _WORDS)
