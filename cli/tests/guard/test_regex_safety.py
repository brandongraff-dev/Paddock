# SPDX-License-Identifier: AGPL-3.0-or-later
"""Every module-level pattern and every pack rule grows linearly (contract 10 G0 build list, 11.3 item 3)."""
from __future__ import annotations

import dataclasses
import importlib
import os
import pkgutil
import re
import tomllib


from support import regexsafety

import paddock_cli.guard as guard_pkg

SCAN_DIRS = ("checks", "pkg", "urlcheck", "initgen", "hooks")


def _modules():
    names = []
    for info in pkgutil.walk_packages(guard_pkg.__path__, "paddock_cli.guard."):
        if info.name.endswith("__main__"):
            continue
        names.append(info.name)
    return names


def _patterns_in(value, depth=0):
    if isinstance(value, re.Pattern):
        yield value
        return
    if depth > 3:
        return
    if isinstance(value, (list, tuple, set, frozenset)):
        for v in value:
            yield from _patterns_in(v, depth + 1)
    elif isinstance(value, dict):
        for v in value.values():
            yield from _patterns_in(v, depth + 1)
    elif dataclasses.is_dataclass(value) and not isinstance(value, type):
        for f in dataclasses.fields(value):
            yield from _patterns_in(getattr(value, f.name, None), depth + 1)
    elif hasattr(value, "_fields"):
        for v in value:
            yield from _patterns_in(v, depth + 1)


def collect():
    found = []
    for name in _modules():
        try:
            mod = importlib.import_module(name)
        except Exception:  # noqa: BLE001  (import errors are other tests' business)
            continue
        adversarial = list(getattr(mod, "ADVERSARIAL", []) or [])
        for attr, value in vars(mod).items():
            if attr.startswith("__"):
                continue
            for rx in _patterns_in(value):
                found.append((name, attr, rx, adversarial))
    return found


def pack_patterns():
    out = []
    packs = os.path.join(os.path.dirname(guard_pkg.__file__), "packs")
    for fname in sorted(os.listdir(packs)):
        if fname.endswith(".toml"):
            with open(os.path.join(packs, fname), "rb") as fh:
                doc = tomllib.load(fh)
            for rule in doc.get("rule", []):
                for key in ("pattern", "negative_pattern"):
                    if key in rule:
                        out.append((fname, rule["id"] + ":" + key, re.compile(rule[key])))
    return out


def test_every_module_level_pattern_is_linear():
    bad = []
    n = 0
    for name, attr, rx, adversarial in collect():
        n += 1
        for p in regexsafety.check_pattern(rx, adversarial):
            bad.append("%s.%s: %s" % (name, attr, p))
    assert n > 0, "the core modules define patterns, so the collector must find some"
    assert bad == []


def test_every_pack_rule_pattern_is_linear():
    bad = []
    for fname, label, rx in pack_patterns():
        for p in regexsafety.check_pattern(rx):
            bad.append("%s %s: %s" % (fname, label, p))
    assert bad == []


def test_the_probe_catches_quadratic_and_exponential_patterns():
    quad = re.compile(r"\s+x")
    assert regexsafety.check_pattern(quad), "a quadratic pattern must be reported"
    expo = re.compile(r"(a+)+$")
    probs = regexsafety.check_pattern(expo)
    assert probs and any("no answer" in p or "grew" in p for p in probs)


def test_the_probe_accepts_linear_patterns():
    for pat in (r"\bpickle\.loads\(\s*request\.", r"[A-Za-z0-9_-]{20,}", r"^abc$", r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b"):
        assert regexsafety.check_pattern(re.compile(pat)) == [], pat


def test_derived_pump_inputs_use_the_repeated_class():
    inputs = dict(regexsafety.inputs_for(re.compile(r"key=\d+z")))
    assert any("'0'" in label for label in inputs)
    first = inputs["pump '0'"][0]
    assert first.startswith("key=") and "0" * 100 in first


def test_adversarial_samples_registered_by_a_module_are_used():
    labels = [label for label, _ in regexsafety.inputs_for(re.compile("x+"), adversarial=["ABAB"])]
    assert "adversarial sample" in labels and "adversarial repeated" in labels


def test_collector_walks_dataclasses_and_containers():
    @dataclasses.dataclass
    class Fam:
        name: str
        rx: re.Pattern

    rx = re.compile("x")
    assert list(_patterns_in((Fam("a", rx),))) == [rx]
    assert list(_patterns_in({"a": [rx]})) == [rx]
