# SPDX-License-Identifier: Apache-2.0
"""Human wording (spec/09-human-wording.md): the verifier owns every sentence.

Templates live in ``data/wording-v1.json``. A template is filled only from integers, strict timestamps,
enumerated tokens, registry names and a few validated shapes; nothing an issuer controls reaches the output as
free text. The forbidden-vocabulary scan used by the conformance runner is here too.
"""
from __future__ import annotations

import json
import re
from typing import Any, Dict, Iterable, List, Optional

from . import limits, timefmt


class WordingError(ValueError):
    """A template, slot or value that is not acceptable."""


_DATA = json.loads(limits.read_data("wording-v1.json").decode("ascii"))  # type: Dict[str, Any]
TIER_PHRASES = dict(_DATA["tier_phrases"])           # type: Dict[str, str]
REASON_PHRASES = dict(_DATA["reason_phrases"])       # type: Dict[str, str]
FORBIDDEN_WORDS = tuple(_DATA["forbidden_words"])
_TEMPLATES = _DATA["templates"]
_HEADLINES = _DATA["headlines"]
_ENUMS = _DATA["enums"]
PROFILE_LINE = _DATA["profile_line"]  # type: str

_INVID = re.compile(r"[a-z][a-z0-9]{0,31}:[a-z0-9][a-z0-9-]{0,63}\Z", re.ASCII)
_SUBJECT = re.compile(r"(?:dns:[a-z0-9]([a-z0-9.-]{0,251}[a-z0-9])?|paddock-estate:e_[a-z2-7]{26})\Z", re.ASCII)
_TOKEN = re.compile(r"[A-Za-z0-9._:-]{1,64}\Z", re.ASCII)
_NAME = re.compile(r"[ !#$%&'()*+,\-./0-9:;<=>?@A-Z\[\]^_a-z|~]{1,120}\Z", re.ASCII)
_PHRASE = re.compile(r"[ !#$%&'()*+,\-./0-9:;<=>?@A-Z\[\]^_`a-z|~]{1,200}\Z", re.ASCII)
_SLOT = re.compile(r"\{([a-z_]+)\}")
_WORD = re.compile(r"[a-z0-9_]+(?:-[a-z0-9_]+)*")


def template_ids() -> List[str]:
    return sorted(_TEMPLATES)


def raw_template(template_id: str) -> str:
    """The template text with ``{slot}`` placeholders (for scans and documentation)."""
    return _TEMPLATES[template_id]["text"]


def tier_phrase(tier: str) -> str:
    try:
        return TIER_PHRASES[tier]
    except KeyError:
        raise WordingError("unknown tier %r" % (tier,)) from None


def reason_phrase(code: str) -> str:
    """Phrase for a public UNKNOWN reason code; an unknown code reads as ``other``."""
    return REASON_PHRASES.get(code, REASON_PHRASES["other"])


def percent_floor(covered: int, universe: int) -> int:
    """``floor(covered * 100 / universe)``: 41 of 42 shows 97, never 98 or 100."""
    if isinstance(covered, bool) or isinstance(universe, bool) or not isinstance(covered, int) or not isinstance(universe, int):
        raise TypeError("integers required")
    if universe < 1 or covered < 0:
        raise ValueError("universe must be at least 1")
    return covered * 100 // universe


def _fill(text: str, slots: Dict[str, str], values: Dict[str, Any], what: str) -> str:
    if set(values) != set(slots):
        raise WordingError("%s needs exactly the slots %s" % (what, sorted(slots)))
    rendered = {}
    for name, kind in slots.items():
        rendered[name] = _check(kind, values[name], name)
    return _SLOT.sub(lambda m: rendered[m.group(1)], text)


def _check(kind: str, value: Any, name: str) -> str:
    if kind == "uint":
        if isinstance(value, bool) or not isinstance(value, int) or not 0 <= value <= limits.MAX_INT:
            raise WordingError("%s must be a non-negative integer" % name)
        return str(value)
    if kind.startswith("enum:"):
        table = _ENUMS[kind[5:]]
        if not isinstance(value, str) or value not in table:
            raise WordingError("%s is not one of %s" % (name, sorted(table)))
        return table[value]
    if not isinstance(value, str):
        raise WordingError("%s must be a string" % name)
    if kind == "time":
        try:
            timefmt.parse(value)
        except timefmt.TimeError:
            raise WordingError("%s must be YYYY-MM-DDTHH:MM:SSZ" % name) from None
        return value
    pattern = {"name": _NAME, "invid": _INVID, "phrase": _PHRASE, "subject": _SUBJECT, "token": _TOKEN}.get(kind)
    if pattern is None:
        raise WordingError("unknown slot type %r" % kind)
    if not pattern.match(value):
        raise WordingError("%s is not a valid %s" % (name, kind))
    return value


def render(template_id: str, **values: Any) -> str:
    """Fill a template. Every slot is validated; a missing or extra slot is an error."""
    t = _TEMPLATES.get(template_id)
    if t is None:
        raise WordingError("unknown template %r" % (template_id,))
    return _fill(t["text"], t["slots"], values, template_id)


def headline(kind: str, **values: Any) -> str:
    """``baseline``, ``accepted``, ``rejected`` or ``unverifiable`` headline lines."""
    h = _HEADLINES.get(kind)
    if h is None:
        raise WordingError("unknown headline %r" % (kind,))
    return _fill(h["text"], h["slots"], values, "headline " + kind)


def profile_line() -> str:
    return PROFILE_LINE


def forbidden_hits(text: str, remove: Iterable[str] = (), words: Optional[Iterable[str]] = None) -> List[str]:
    """Forbidden words found in ``text`` after removing exactly the strings in ``remove`` (the footer, the
    limits text, ids and domains taken from the input). Whole words, case-insensitive; a hyphenated compound
    counts when it, or any part of it, is listed. Returns the sorted unique hits."""
    banned = set(w.lower() for w in (FORBIDDEN_WORDS if words is None else words))
    for r in remove:
        if r:
            text = text.replace(r, " ")
    hits = set()
    for token in _WORD.findall(text.lower()):
        if token in banned:
            hits.add(token)
        for part in token.split("-"):
            if part in banned:
                hits.add(part)
    return sorted(hits)
