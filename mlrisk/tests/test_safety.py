"""Guardrails: mlrisk learns from the platform's OWN data to rank + flag.

It must NOT make external/outbound network calls, execute untrusted data, or
contain exploit-generation / attack-planning machinery. These are static source
scans over ``app/`` — belt-and-braces alongside the behavioural tests.
"""
from __future__ import annotations

import pathlib
import re

APP = pathlib.Path(__file__).resolve().parents[1] / "app"


def _py_files() -> list[pathlib.Path]:
    return [p for p in APP.rglob("*.py") if "__pycache__" not in str(p)]


def test_no_outbound_http_client() -> None:
    """No HTTP client is constructed — aiohttp is used only as a server."""
    banned = [
        "ClientSession(", "requests.get", "requests.post", "httpx.",
        "urllib.request", "session.get(", "session.post(",
    ]
    offenders: list[str] = []
    for py in _py_files():
        for line in py.read_text().splitlines():
            if any(b in line for b in banned):
                offenders.append(f"{py.name}: {line.strip()}")
    assert offenders == [], offenders


def test_no_external_urls() -> None:
    """No http(s) URLs anywhere (DB/redis DSNs are not external fetches)."""
    offenders: list[str] = []
    for py in _py_files():
        for host in re.findall(r"https?://([^/\"'\s]+)", py.read_text()):
            offenders.append(f"{py.name}: {host}")
    assert offenders == [], offenders


def test_no_dynamic_execution_of_data() -> None:
    """The service never executes data it reads (findings, source, etc.)."""
    banned = [
        "eval(", "exec(", "os.system(", "subprocess.", "pickle.load",
        "pickle.loads", "yaml.load(", "__import__(",
    ]
    offenders: list[str] = []
    for py in _py_files():
        for line in py.read_text().splitlines():
            if any(b in line for b in banned):
                offenders.append(f"{py.name}: {line.strip()}")
    assert offenders == [], offenders


def test_no_exploit_or_attack_generation_wording() -> None:
    """No offensive-tooling vocabulary. (attack_path / exploitability as a read
    feature are fine; generation/planning verbs are not.)"""
    banned = [
        "generate exploit", "generate_exploit", "exploit_code", "exploit generation",
        "proof-of-concept", "proof of concept", "reverse shell", "metasploit",
        "attack plan", "plan an attack", "weaponize", "payload generation",
    ]
    offenders: list[str] = []
    for py in _py_files():
        text = py.read_text().lower()
        for b in banned:
            if b in text:
                offenders.append(f"{py.name}: {b}")
    assert offenders == [], offenders
