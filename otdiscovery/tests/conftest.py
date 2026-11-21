"""Shared fixtures for the otdiscovery suite.

Everything here is pure-Python and offline: fingerprinting, OT-protocol
identification, exposure logic and the safety guard need no database and no
network. The CVE matcher is exercised with an injected in-memory fetcher.
"""
from __future__ import annotations

import pathlib

import pytest

FIXTURES = pathlib.Path(__file__).parent / "fixtures"


def load_capture(name: str = "sample_capture.pcap") -> bytes:
    return (FIXTURES / name).read_bytes()


@pytest.fixture
def sample_capture() -> bytes:
    return load_capture()
