#!/usr/bin/env python3
"""Stress-test the scope normaliser against real-world URL parsers.

Generates N random hostile target strings and, for each one the normaliser
ACCEPTS, asks an RFC 3986 parser (urllib) and a WHATWG parser (Ada, the one
inside Node.js) which host they would connect to. Any disagreement is a
potential scope bypass. Optionally compares against another revision of
orchestrator/app/scope.py to show what the hardening bought.

    pip install ada-url
    python hardening/stress_scope.py --n 200000
    python hardening/stress_scope.py --n 200000 --baseline HEAD~1
"""
from __future__ import annotations

import argparse
import ipaddress
import importlib
import random
import subprocess
import sys
import tempfile
import time
from collections import Counter
from pathlib import Path
from urllib.parse import urlsplit

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "orchestrator"))
from app import scope as current  # noqa: E402

try:
    from ada_url import URL as AdaURL
except ImportError:
    AdaURL = None

FRAGMENTS = [
    "http://", "https://", "HTTP://", "http:/", "http:", "//", "ftp://", "ws://",
    "target.com", "evil.com", "sub.target.com", "127.0.0.1", "0x7f.1", "2130706433",
    "169.254.169.254", "[::1]", "[::ffff:a9fe:a9fe]", "ｅｖｉｌ.com", "xn--e1a", "１２７",
    "@", "#", "?", "/", "\\", ":", ";", ".", "..", "%40", "%2f", "%2e", "%00",
    "\t", "\n", "\r", " ", "\x00", "​", "。", ":80", ":443", ":0", ":",
    "user:pw@", "[", "]", "*", "&", "=", ",", "'", "!", "$", "~",
]


def gen(rng: random.Random) -> str:
    if rng.random() < 0.8:
        return "".join(rng.choice(FRAGMENTS) for _ in range(rng.randint(1, 9)))
    alphabet = "abcxyz.:/@#?\\[]%019\t -_。１"
    return "".join(rng.choice(alphabet) for _ in range(rng.randint(1, 28)))


def canon(host):
    if not host:
        return None
    h = host.strip("[]")
    try:
        if ":" in h:
            return current._canonical_ipv6(h)
        if not h.isascii():
            h = h.encode("idna").decode()
        v4 = current._canonical_ipv4(h.lower())
        return v4 if v4 is not None else current._canonical_hostname(h)
    except (ValueError, UnicodeError):
        return None


def oracles(t: str):
    t = t.strip(" ")  # callers trim plain spaces
    url = t if "://" in t else f"http://{t}"
    if "://" not in t:
        try:  # a tool turns a bare IPv6 target into http://[addr]/
            ipaddress.IPv6Address(t)
            url = f"http://[{t}]/"
        except ValueError:
            pass
    out = {}
    try:
        out["rfc3986"] = canon(urlsplit(url).hostname)
    except ValueError:
        out["rfc3986"] = None
    if AdaURL is not None:
        try:
            out["whatwg"] = canon(AdaURL(url).hostname)
        except ValueError:
            out["whatwg"] = None
    return out


def load_baseline(rev: str):
    src = subprocess.check_output(
        ["git", "-C", str(ROOT), "show", f"{rev}:orchestrator/app/scope.py"], text=True
    )
    tmp = Path(tempfile.mkdtemp())
    pkg = tmp / "baseline_app"
    pkg.mkdir()
    (pkg / "__init__.py").write_text("")
    (pkg / "config.py").write_text((ROOT / "orchestrator/app/config.py").read_text())
    (pkg / "scope.py").write_text(src)
    sys.path.insert(0, str(tmp))
    return importlib.import_module("baseline_app.scope").normalize


def run(name, normalize, cases):
    accepted = differentials = 0
    classes: Counter[str] = Counter()
    examples: list[str] = []
    t0 = time.perf_counter()
    for t in cases:
        try:
            ours = normalize(t)
        except Exception:  # a crash is also a finding
            classes["crash"] += 1
            continue
        if not ours:
            continue
        accepted += 1
        for parser, theirs in oracles(t).items():
            if theirs is not None and theirs != ours:
                differentials += 1
                key = next((c for c in "#?\\\t\n%@" if c in t), "other")
                classes[f"{parser}:{key!r}"] += 1
                if len(examples) < 6:
                    examples.append(f"{t!r}: ours={ours!r} {parser}={theirs!r}")
                break
    dt = time.perf_counter() - t0
    print(f"\n[{name}] {len(cases):,} targets in {dt:.1f}s "
          f"({len(cases)/dt:,.0f}/s) | accepted {accepted:,} | "
          f"DIFFERENTIALS {differentials:,} | crashes {classes['crash']}")
    for k, v in classes.most_common(8):
        if k != "crash":
            print(f"    {v:>7,}  {k}")
    for e in examples:
        print("    e.g.", e)
    return differentials


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--n", type=int, default=100_000)
    ap.add_argument("--seed", type=int, default=1337)
    ap.add_argument("--baseline", help="git revision to compare against (e.g. HEAD)")
    a = ap.parse_args()
    if AdaURL is None:
        print("note: ada-url not installed; WHATWG oracle disabled (pip install ada-url)")
    rng = random.Random(a.seed)
    cases = [gen(rng) for _ in range(a.n)]
    if a.baseline:
        run(f"baseline {a.baseline}", load_baseline(a.baseline), cases)
    bad = run("current", current.normalize, cases)
    sys.exit(1 if bad else 0)


if __name__ == "__main__":
    main()
