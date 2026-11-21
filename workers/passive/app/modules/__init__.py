"""Passive discovery modules.

Each module exposes `async def run(domain_or_target, ctx) -> ModuleResult`.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any


@dataclass
class ModuleResult:
    """What a module returns after one invocation.

    `assets` and `edges` are already scope-filtered by the module (or by
    `ModuleContext.push`). The main loop aggregates these into the scan's
    result_summary and pushes to the orchestrator in bulk.
    """
    module: str
    assets: list[dict[str, Any]] = field(default_factory=list)
    edges: list[dict[str, Any]] = field(default_factory=list)
    findings: list[dict[str, Any]] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)
    source_calls: int = 0
