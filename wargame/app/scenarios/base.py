"""Scenario contract for the Proving Ground.

A *scenario* knows how to prove one class of hop against an isolated replica:

  1. ``matches(ctx)``      does this scenario apply to the component/finding?
  2. ``build_spec(ctx)``   the replica to stand up in its CURRENT (suspect) state
  3. ``probe(runner, r)``  exercise the hop IN THE SANDBOX -> a verdict + evidence
  4. ``fixed_spec(ctx)``   the replica with the candidate fix applied
                           (e.g. a patched image tag), or None when the fix is a
                           config change expressed by overriding build_spec
  5. ``fix_ref(ctx)``      a human description of that fix

The prover runs step 2-3 to get the BEFORE verdict (expected: vulnerable),
applies the fix and re-runs to get the AFTER verdict (expected: not_vulnerable),
and records a signed before/after proof. Scenarios NEVER touch a live system:
they only ever receive a ``ScenarioRunner`` that is mediated by the isolation
guard, so every command and probe lands inside the sandbox network.

Scenario code lives here (reviewable in one place); the ``wargame_scenarios``
table only stores each scenario's catalogue row + matcher config.
"""
from __future__ import annotations

import abc
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Optional, Protocol

from ..sandbox.types import ExecResult, Replica, SandboxSpec


class Verdict(str, Enum):
    VULNERABLE = "vulnerable"
    NOT_VULNERABLE = "not_vulnerable"
    INCONCLUSIVE = "inconclusive"


# Scenario categories mirror wargame_scenarios.category.
CATEGORIES = frozenset(
    {"cve_repro", "default_cred", "unauth_access", "exposed_service",
     "misconfig", "segmentation", "other"}
)


@dataclass
class HttpProbe:
    """Result of an HTTP probe run from inside the sandbox against a replica."""

    status: int = 0
    headers: dict[str, str] = field(default_factory=dict)
    body_excerpt: str = ""
    error: Optional[str] = None

    @property
    def ok(self) -> bool:
        return self.error is None and self.status > 0


class ScenarioRunner(Protocol):
    """The ONLY way a scenario interacts with a replica. Every method is
    mediated by the isolation guard: the target is always the given replica,
    inside the internal-only sandbox network. A scenario cannot obtain a raw
    socket or the backend, so it cannot reach anything but the replica."""

    async def exec_in(
        self, replica: Replica, argv: tuple[str, ...], *, timeout_sec: int = 30
    ) -> ExecResult:
        """Run a command inside the replica (or the scenario's toolbox sidecar)."""
        ...

    async def http(
        self, replica: Replica, path: str = "/", *, method: str = "GET",
        timeout_sec: int = 15, headers: Optional[dict[str, str]] = None,
    ) -> HttpProbe:
        """HTTP request to the replica's internal endpoint, from inside the net."""
        ...

    async def tcp_open(self, replica: Replica, *, timeout_sec: int = 5) -> bool:
        """True if the replica's internal port accepts a TCP connection."""
        ...


@dataclass
class ScenarioCtx:
    """Everything a scenario needs about the hop under test.

    Built by the prover from the attack-path hop + the component (SBOM /
    technology asset) + the finding that flagged it.
    """

    #: Component being replicated: {product, version, image, purl, source,...}.
    component: dict[str, Any]
    #: The finding that raised this hop, if any (rule_id, rule_source, cvss...).
    finding: dict[str, Any] = field(default_factory=dict)
    #: Attack-path context: {attack_path_id, target_asset_id, hop_index, ...}.
    path: dict[str, Any] = field(default_factory=dict)
    #: The scenario's own catalogue spec (wargame_scenarios.spec).
    spec: dict[str, Any] = field(default_factory=dict)

    # -- convenience accessors ------------------------------------------------
    @property
    def product(self) -> str:
        return str(self.component.get("product") or self.component.get("component") or "").lower()

    @property
    def version(self) -> str:
        return str(self.component.get("version") or "")

    @property
    def rule_source(self) -> str:
        return str(self.finding.get("rule_source") or "")

    @property
    def rule_id(self) -> str:
        return str(self.finding.get("rule_id") or "")


@dataclass
class ScenarioResult:
    """A scenario's verdict for one phase (before or after), plus evidence."""

    verdict: Verdict
    summary: str
    #: Redacted, size-capped evidence (commands run, status codes, excerpts).
    evidence: dict[str, Any] = field(default_factory=dict)

    @classmethod
    def vulnerable(cls, summary: str, **ev: Any) -> "ScenarioResult":
        return cls(Verdict.VULNERABLE, summary, dict(ev))

    @classmethod
    def not_vulnerable(cls, summary: str, **ev: Any) -> "ScenarioResult":
        return cls(Verdict.NOT_VULNERABLE, summary, dict(ev))

    @classmethod
    def inconclusive(cls, summary: str, **ev: Any) -> "ScenarioResult":
        return cls(Verdict.INCONCLUSIVE, summary, dict(ev))


class Scenario(abc.ABC):
    """Base class for a proving-ground scenario."""

    #: Stable catalogue id, e.g. "cve-container-repro". Matches wargame_scenarios.id.
    id: str = ""
    title: str = ""
    description: str = ""
    category: str = "other"
    technique: Optional[str] = None

    def catalogue_row(self) -> dict[str, Any]:
        """The row this scenario contributes to wargame_scenarios."""
        if self.category not in CATEGORIES:
            raise ValueError(f"{self.id}: bad category {self.category!r}")
        return {
            "id": self.id,
            "title": self.title,
            "description": self.description,
            "category": self.category,
            "technique": self.technique,
            "enabled": True,
            "spec": self.default_spec(),
        }

    def default_spec(self) -> dict[str, Any]:
        """Default catalogue spec (matcher config). Overridable."""
        return {}

    @abc.abstractmethod
    def matches(self, ctx: ScenarioCtx) -> bool:
        """Does this scenario apply to the component/finding in ``ctx``?"""

    @abc.abstractmethod
    def build_spec(self, ctx: ScenarioCtx) -> SandboxSpec:
        """The replica to stand up in its CURRENT (suspect) state."""

    @abc.abstractmethod
    async def probe(
        self, runner: ScenarioRunner, replica: Replica, ctx: ScenarioCtx
    ) -> ScenarioResult:
        """Exercise the hop against the replica and return a verdict."""

    def fixed_spec(self, ctx: ScenarioCtx) -> Optional[SandboxSpec]:
        """The replica with the candidate fix applied (e.g. a patched image),
        or None when there is no automatic fix to prove. Default: no fix."""
        return None

    def fix_ref(self, ctx: ScenarioCtx) -> str:
        """Human description of the candidate fix."""
        return ""
