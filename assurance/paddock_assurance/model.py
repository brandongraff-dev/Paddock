"""The invariant document (DSL v0) as strict pydantic models.

Closed vocabulary on purpose: no free-form queries, no expressions, nothing Turing-complete.
Unknown keys are rejected everywhere. Set-like lists are normalised (sorted, de-duplicated) so
the canonical digest does not depend on how an author ordered them.
"""
from __future__ import annotations

import datetime as dt
import re
from typing import Any, Literal, Optional

from pydantic import BaseModel, ConfigDict, Field, ValidationInfo, field_validator, model_validator

from . import hostexpr as X
from . import ports as P
from .tier import Tier

API_VERSION = "paddock.dev/invariant/v1"
_LITERAL_ASSERTS = ("unreachable", "exposes-only", "covered")

# These are applied with ``fullmatch``: ``$`` also matches before a trailing newline, which made
# ``acme:x\n`` a second, distinct-looking id. ``[0-9]`` rather than ``\d`` (which is any Unicode digit).
ID_RE = re.compile(r"[a-z][a-z0-9]{0,31}:[a-z0-9][a-z0-9-]{0,63}")
SEL_VALUE_RE = re.compile(r"[A-Za-z0-9._:/-]{1,64}")
DURATION_RE = re.compile(r"([0-9]{1,4})([mhd])")
# The platform derives a finding's identity from CVE/GHSA-looking tokens anywhere in its rule id
# (``invariant:<id>@<target>``), so an invariant id that carries one makes every finding of that
# invariant on a shared asset collapse into one. Deliberately a superset of what the platform
# extracts (no word boundaries, looser GHSA alphabet): an id never needs such a token.
VULN_TOKEN_RE = re.compile(r"cve-[0-9]{4}-[0-9]{4,}|ghsa(?:-[a-z0-9]{4}){3}", re.IGNORECASE)
MAX_AGE_LIMIT = dt.timedelta(days=30)

# Free text must describe, never instruct. Deliberately small and aligned in spirit with
# correlation/app/engine/policy.py (this package does not import from other services).
_REJECT = ("payload", "msfvenom", "reverse shell", "nc -e", "union select", "/bin/sh",
           "powershell -enc")


def parse_duration(text: str) -> dt.timedelta:
    m = DURATION_RE.fullmatch(text) if isinstance(text, str) else None
    if not m:
        raise ValueError("duration must look like 90m, 24h or 7d")
    n, unit = int(m.group(1)), m.group(2)
    delta = dt.timedelta(minutes=n) if unit == "m" else dt.timedelta(hours=n) if unit == "h" \
        else dt.timedelta(days=n)
    if delta <= dt.timedelta(0) or delta > MAX_AGE_LIMIT:
        raise ValueError("duration must be between 1m and 30d")
    return delta


def _check_text(value: Optional[str]) -> Optional[str]:
    if value is None:
        return value
    low = value.lower()
    for tok in _REJECT:
        if tok in low:
            raise ValueError(f"text may describe a control, not an attack step (found {tok!r})")
    return value


# ``parse_invariant`` validates with ``context={ASSERT_PROBLEMS: []}`` so that a bad ``assert:`` does not abort the
# whole model and hide every other schema error (P2.1 D36). The bad assert is recorded in the list and replaced by
# a PLACEHOLDER literal so field validation can go on. The placeholder is never a valid document: ``_shape`` refuses
# it with ``PLACEHOLDER_REFUSED`` (which ``parse_invariant`` drops from the report), so no caller can obtain an
# ``Invariant`` that judges ``covered`` where its author wrote something else.
ASSERT_PROBLEMS = "assert_problems"
PLACEHOLDER = "covered"
PLACEHOLDER_REFUSED = "assert: placeholder is not a valid invariant"


def _assert_problems(info: Optional[ValidationInfo]) -> Optional[list]:
    """The collecting list of this validation run, or None when nobody asked for collection (then every
    validator raises exactly as it always did)."""
    ctx = getattr(info, "context", None)
    if isinstance(ctx, dict):
        found = ctx.get(ASSERT_PROBLEMS)
        if isinstance(found, list):
            return found
    return None


def _listify(v: Any) -> Any:
    if v is None:
        return v
    if isinstance(v, (str, int)) and not isinstance(v, bool):
        return [str(v)]
    return v


class _Strict(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True, populate_by_name=True)


class Selector(_Strict):
    """Picks graph nodes. All present fields must match (AND); values within a field are OR."""

    id: Optional[tuple[str, ...]] = None
    zone: Optional[tuple[str, ...]] = None
    tag: Optional[tuple[str, ...]] = None
    kind: Optional[tuple[str, ...]] = None
    cls: Optional[tuple[str, ...]] = Field(default=None, alias="class")

    @field_validator("id", "zone", "tag", "kind", "cls", mode="before")
    @classmethod
    def _as_list(cls, v: Any) -> Any:
        return _listify(v)

    @field_validator("id", "zone", "tag", "kind", "cls", mode="after")
    @classmethod
    def _norm(cls, v: Optional[tuple[str, ...]]) -> Optional[tuple[str, ...]]:
        if v is None:
            return v
        if not v:
            raise ValueError("selector field must not be empty")
        for item in v:
            if not isinstance(item, str) or not SEL_VALUE_RE.fullmatch(item):
                raise ValueError(f"bad selector value {item!r}")
        return tuple(sorted(set(v)))

    @model_validator(mode="after")
    def _non_empty(self) -> "Selector":
        if not any((self.id, self.zone, self.tag, self.kind, self.cls)):
            raise ValueError("empty selector (omit the key to mean 'everything')")
        return self


class Subjects(_Strict):
    from_: Optional[Selector] = Field(default=None, alias="from")
    to: Optional[Selector] = None


class Via(_Strict):
    protocols: tuple[Literal["icmp", "tcp", "udp"], ...] = ("icmp", "tcp", "udp")
    ports: Optional[str] = None
    max_hops: int = Field(default=8, ge=1, le=16)
    # Application boundary: nodes matching this selector can be reached, but the search does not
    # continue *through* them (passing one needs an application-layer compromise, which is a
    # different question). Part of the digest, and reported in every result.
    stop_at: Optional[Selector] = None

    @field_validator("protocols", mode="before")
    @classmethod
    def _protocols(cls, v: Any) -> Any:
        return _listify(v)

    @field_validator("protocols", mode="after")
    @classmethod
    def _protocols_norm(cls, v: tuple[str, ...]) -> tuple[str, ...]:
        if not v:
            raise ValueError("protocols must not be empty")
        return tuple(sorted(set(v)))

    @field_validator("ports", mode="before")
    @classmethod
    def _ports(cls, v: Any) -> Any:
        return None if v is None else P.format_ports(P.parse_ports(v))


class Allow(_Strict):
    """An explicit, expiring, audited exception. ``expires`` is inclusive and mandatory."""

    to: Selector
    ports: Optional[str] = None
    reason: str = Field(min_length=3, max_length=300)
    expires: dt.date

    @field_validator("ports", mode="before")
    @classmethod
    def _ports(cls, v: Any) -> Any:
        return None if v is None else P.format_ports(P.parse_ports(v))

    @field_validator("reason")
    @classmethod
    def _reason(cls, v: str) -> str:
        return _check_text(v) or v


class Evidence(_Strict):
    min_tier: Tier = Tier.configured
    max_age: str = "24h"
    # Active confirmation of counterexamples arrives in P5. Accepted and recorded, not yet run.
    confirm: Literal["none", "sample", "all"] = "none"

    @field_validator("max_age")
    @classmethod
    def _max_age(cls, v: str) -> str:
        parse_duration(v)
        return v


class Coverage(_Strict):
    """Policy floor on the share of *known* assets with live, fresh, sufficient evidence."""

    require: float = Field(default=0.95, ge=0.0, le=1.0)


FixId = Literal["restrict_port_to_cidr", "firewall_default_deny_inbound",
                "disable_ssh_password_auth", "disable_unit", "isolate_host", "cloud_sg_change_pr"]


class OnViolation(_Strict):
    finding: bool = True
    propose: tuple[FixId, ...] = ()

    @field_validator("propose", mode="after")
    @classmethod
    def _norm(cls, v: tuple[str, ...]) -> tuple[str, ...]:
        return tuple(sorted(set(v)))


class Invariant(_Strict):
    apiVersion: Literal["paddock.dev/invariant/v1"]
    id: str
    title: str = Field(min_length=3, max_length=160)
    description: Optional[str] = Field(default=None, max_length=2000)
    severity: Literal["info", "low", "medium", "high", "critical"] = "high"
    subjects: Subjects = Subjects()
    # ``host-config`` is what a predicate / all / any / not mapping becomes: the structured tree is
    # in ``expr`` (excluded from model_dump; ``parse.canonical_json`` puts its canonical form into
    # the digest). Consumers keep reading ``assert_`` as a plain string.
    assert_: Literal["unreachable", "exposes-only", "covered", "host-config"] = Field(alias="assert")
    expr: Any = Field(default=None, exclude=True, repr=False)
    via: Via = Via()
    ports: Optional[str] = None
    allow: tuple[Allow, ...] = ()
    evidence: Evidence = Evidence()
    coverage: Coverage = Coverage()
    on_violation: OnViolation = OnViolation()

    @model_validator(mode="before")
    @classmethod
    def _host_assert(cls, data: Any, info: ValidationInfo) -> Any:
        """``assert:`` is a literal, or a predicate / ``{all|any|not: ...}`` (host-config).

        A bad ``assert:`` raises, unless the caller asked for collection (``context={'assert_problems': []}``):
        then the problem is appended and a placeholder takes the assert's place so the other errors still surface."""
        if not isinstance(data, dict):
            return data
        if "expr" in data:
            raise ValueError("expr: unknown key (write the predicate under assert)")
        keys = [k for k in ("assert", "assert_") if k in data]
        if len(keys) != 1:
            return data
        raw = data[keys[0]]
        if isinstance(raw, str) and raw in _LITERAL_ASSERTS:
            return data
        collected = _assert_problems(info)

        def bad(message: str) -> Any:
            if collected is None:
                raise ValueError(message)
            collected.append(("assert", message))
            return dict(data, **{keys[0]: PLACEHOLDER})

        if raw is None or isinstance(raw, (bool, int, float, list)):
            return bad("assert: must be unreachable, exposes-only, covered, a predicate "
                       "string or a mapping with all, any or not")
        try:
            tree = X.parse_assertion(raw)
        except X.ExprError as exc:
            hint = ""
            if isinstance(raw, str) and not any(c in raw for c in " (=<>!"):
                hint = " (not one of unreachable, exposes-only, covered)"
            return bad(f"{exc}{hint}")
        out = dict(data)
        out[keys[0]] = "host-config"
        out["expr"] = tree
        # A host invariant that does not choose a floor gets the strict one: an unknown host is not
        # a pass. (Std invariants say 1.0 themselves; a lower floor is an explicit, digested choice.)
        cov = out.get("coverage")
        if cov is None:
            out["coverage"] = {"require": 1.0}
        elif isinstance(cov, dict) and "require" not in cov:
            out["coverage"] = dict(cov, require=1.0)
        return out

    @field_validator("id")
    @classmethod
    def _id(cls, v: str) -> str:
        if not ID_RE.fullmatch(v):
            raise ValueError("id must look like 'std:no-internet-to-datastore' or 'acme:my-rule'")
        if VULN_TOKEN_RE.search(v):
            raise ValueError("id must not contain a CVE or GHSA identifier (CVE-YYYY-NNNN, "
                             "GHSA-xxxx-xxxx-xxxx): the platform would treat every finding of "
                             "this invariant as that vulnerability and merge them")
        return v

    @field_validator("title", "description")
    @classmethod
    def _text(cls, v: Optional[str]) -> Optional[str]:
        return _check_text(v)

    @field_validator("ports", mode="before")
    @classmethod
    def _ports(cls, v: Any) -> Any:
        return None if v is None else P.format_ports(P.parse_ports(v))

    @model_validator(mode="after")
    def _shape(self, info: ValidationInfo) -> "Invariant":
        if _assert_problems(info):
            # a placeholder assert stands in for a bad one: the shape rules would judge the PLACEHOLDER (and add
            # noise like "'covered' needs subjects.to"), and the model must never come out of validation
            raise ValueError(PLACEHOLDER_REFUSED)
        if (self.assert_ == "host-config") != (self.expr is not None):
            raise ValueError("assert: 'host-config' is not written literally; give a predicate "
                             "or a mapping with all, any or not")
        if self.assert_ == "host-config":
            if self.subjects.to is None:
                raise ValueError("a host-config assertion needs subjects.to (the hosts it judges)")
            if self.subjects.from_ is not None:
                raise ValueError("a host-config assertion takes no subjects.from")
            if self.ports is not None or self.allow or self.via != Via():
                raise ValueError("a host-config assertion takes no ports, allow or via")
        elif self.assert_ == "unreachable":
            if self.subjects.from_ is None or self.subjects.to is None:
                raise ValueError("'unreachable' needs both subjects.from and subjects.to")
            if self.ports is not None or any(a.ports for a in self.allow):
                raise ValueError("'ports' belongs to 'exposes-only'; use via.ports to filter edges")
        elif self.assert_ == "covered":
            # A statement about our own evidence, not about traffic: it names the nodes that must
            # be observable, and nothing else is meaningful (no source, ports, hops or exceptions).
            if self.subjects.to is None:
                raise ValueError("'covered' needs subjects.to (the nodes that must be covered)")
            if self.subjects.from_ is not None:
                raise ValueError("'covered' takes no subjects.from")
            if self.ports is not None or self.allow or self.via != Via():
                raise ValueError("'covered' takes no ports, allow or via")
        else:
            if self.subjects.from_ is None:
                raise ValueError("'exposes-only' needs subjects.from (e.g. the internet zone)")
            if self.ports is None:
                raise ValueError("'exposes-only' needs 'ports' (the allow-list)")
        return self
