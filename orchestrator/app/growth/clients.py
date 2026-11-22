"""Where the engine gets its DNS resolver and CT client.

A single seam so tests install fakes (no network, ever) and a deployment can
swap in a caching resolver without touching the engine.
"""
from __future__ import annotations

from typing import Callable

from .engine import CTClient, Resolver, default_clients

ClientFactory = Callable[[], tuple[Resolver, CTClient]]

_factory: ClientFactory | None = None


def set_client_factory(f: ClientFactory | None) -> None:
    global _factory
    _factory = f


def get_clients() -> tuple[Resolver, CTClient]:
    return (_factory or default_clients)()
