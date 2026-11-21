"""YAML DSL loader + validator.

Two rule kinds:

* ChainRule — declarative `all_of` predicates. Evaluated in `chain.py` by
  translating each predicate into a parameterized SQL filter.
* PolicyRule — a hand-written SELECT that returns asset_ids to flag.
  The SQL is parsed and anything other than a single SELECT is refused.

All rule YAMLs are run through two safety gates before load:

1. A keyword blocklist that rejects any "offensive" verb — `exploit`,
   `payload`, `shell`, `cmd:`, `injection_string`, etc. — so malicious
   or lazy authors can't slip exploitation guidance into impact text.

2. SQL in policy rules is parsed with sqlglot and refused if it contains
   DDL (CREATE/DROP/ALTER/TRUNCATE) or any data-modifying statement
   (INSERT/UPDATE/DELETE/COPY), or if it isn't a single statement.
"""
from __future__ import annotations

import logging
import os
import re
from pathlib import Path
from typing import Any, Literal, Optional

import yaml
from pydantic import BaseModel, Field, ValidationError, field_validator

try:  # sqlglot is only needed for policy-rule validation.
    import sqlglot
    from sqlglot import exp as sqlglot_exp

    _HAS_SQLGLOT = True
except Exception:  # pragma: no cover
    _HAS_SQLGLOT = False

log = logging.getLogger(__name__)


Severity = Literal["info", "low", "medium", "high", "critical"]
Scope = Literal["same_host", "same_domain", "same_cidr", "same_org"]

# Subdirectories under the rules root that `RuleLoader` must not treat as
# chain/policy YAML. `attack/` is the ATT&CK technique map, loaded by
# engine.attack_mapping instead.
_NON_RULE_DIRS = frozenset({"attack"})


# ----------------------------------------------------------------------------
# Safety gates
# ----------------------------------------------------------------------------

class UnsafeRuleError(ValueError):
    """Raised when a YAML rule contains disallowed content."""


# Keys we refuse to see anywhere in the YAML. These names imply the rule
# author wants to describe how to attack something, which is out of scope
# for a defensive platform.
_FORBIDDEN_KEYS = frozenset(
    {
        "exploit",
        "exploits",
        "payload",
        "payloads",
        "shell",
        "shellcode",
        "cmd",
        "command",
        "injection_string",
        "attack_script",
        "reverse_shell",
        "post_exploitation",
    }
)

# Narratives that mention these tokens are rejected as describing
# exploitation steps rather than impact.
_FORBIDDEN_NARRATIVE_TOKENS = re.compile(
    r"\b(curl\s+-|wget\s+http|bash\s+-c|/bin/sh|nc\s+-e|msfvenom|"
    r"python\s+-c\s+['\"]|powershell\s+-enc|0x[0-9a-f]{8,}|"
    r"reverse\s+shell|rev\s*shell|drop\s+table|union\s+select)\b",
    re.IGNORECASE,
)

# SQL statement kinds we refuse in policy rules. sqlglot assigns one of
# these as the root expression type.
_FORBIDDEN_SQL_EXPRS: tuple[type, ...] = ()
if _HAS_SQLGLOT:
    _candidate_exprs = (
        "Create",
        "Drop",
        "Alter",
        "AlterTable",
        "AlterColumn",
        "Insert",
        "Update",
        "Delete",
        "Merge",
        "Copy",
        "TruncateTable",
        "Truncate",
    )
    _FORBIDDEN_SQL_EXPRS = tuple(
        getattr(sqlglot_exp, n)
        for n in _candidate_exprs
        if hasattr(sqlglot_exp, n)
    )

_FORBIDDEN_SQL_REGEX = re.compile(
    r"\b(CREATE|DROP|ALTER|TRUNCATE|INSERT|UPDATE|DELETE|GRANT|"
    r"REVOKE|COPY|MERGE|ATTACH|DETACH|VACUUM|CLUSTER|REINDEX|"
    r"REFRESH\s+MATERIALIZED)\b",
    re.IGNORECASE,
)


def _walk_keys(node: Any) -> list[str]:
    """Yield every mapping key that appears anywhere in a parsed YAML tree."""
    out: list[str] = []
    stack: list[Any] = [node]
    while stack:
        cur = stack.pop()
        if isinstance(cur, dict):
            for k, v in cur.items():
                out.append(str(k))
                stack.append(v)
        elif isinstance(cur, list):
            stack.extend(cur)
    return out


def validate_narrative_text(text: str) -> None:
    """Refuse narrative text that reads like an exploitation guide."""
    if not text:
        return
    m = _FORBIDDEN_NARRATIVE_TOKENS.search(text)
    if m:
        raise UnsafeRuleError(
            f"narrative/impact contains disallowed token: {m.group(0)!r} "
            "(impact text must describe outcomes, not exploitation steps)"
        )


def validate_sql(query: str) -> None:
    """Refuse DDL/DML in a policy query. Falls back to regex if sqlglot
    isn't installed."""
    q = query.strip().rstrip(";").strip()
    if not q:
        raise UnsafeRuleError("empty query")
    if ";" in q:
        raise UnsafeRuleError("query must be a single statement (no ';')")

    if _HAS_SQLGLOT:
        try:
            parsed = sqlglot.parse(q, read="postgres")
        except sqlglot.errors.ParseError as e:
            raise UnsafeRuleError(f"query failed to parse: {e}") from e
        parsed = [p for p in parsed if p is not None]
        if len(parsed) != 1:
            raise UnsafeRuleError(
                "query must be a single statement"
            )
        root = parsed[0]
        if isinstance(root, _FORBIDDEN_SQL_EXPRS):
            raise UnsafeRuleError(
                f"query uses disallowed statement kind: "
                f"{type(root).__name__}"
            )
        if not isinstance(root, (sqlglot_exp.Select, sqlglot_exp.Union)):
            raise UnsafeRuleError(
                f"query must be SELECT/UNION; got {type(root).__name__}"
            )
        # A SELECT can still wrap a CTE whose inside mutates things.
        for child in root.walk():
            # sqlglot `walk` yields (node,) tuples in some versions; be
            # tolerant.
            node = child[0] if isinstance(child, tuple) else child
            if isinstance(node, _FORBIDDEN_SQL_EXPRS):
                raise UnsafeRuleError(
                    f"query contains disallowed subexpression: "
                    f"{type(node).__name__}"
                )
    else:  # pragma: no cover
        if _FORBIDDEN_SQL_REGEX.search(q):
            raise UnsafeRuleError(
                "query contains disallowed keyword (DDL or DML)"
            )


def _check_forbidden_keys(doc: Any, source: str) -> None:
    for key in _walk_keys(doc):
        if key.lower() in _FORBIDDEN_KEYS:
            raise UnsafeRuleError(
                f"{source}: forbidden key '{key}' present"
            )


# ----------------------------------------------------------------------------
# Pydantic models for the YAML DSL
# ----------------------------------------------------------------------------

class FindingPredicate(BaseModel):
    """Match against a `findings` row."""

    rule_source: Optional[str] = None
    rule_id: Optional[str] = None
    rule_id_match: Optional[str] = Field(
        default=None, description="Regex applied to findings.rule_id"
    )
    severity_min: Optional[Severity] = None
    cvss_min: Optional[float] = Field(default=None, ge=0.0, le=10.0)
    epss_min: Optional[float] = Field(default=None, ge=0.0, le=1.0)
    known_exploited: Optional[bool] = None
    status: Optional[str] = "open"
    # Match on the asset the finding is attached to.
    asset_kind: Optional[str] = None
    asset_metadata: Optional[dict[str, Any]] = None
    # Free-form JSONB matchers against findings.evidence / findings.metadata
    evidence: Optional[dict[str, Any]] = None
    metadata: Optional[dict[str, Any]] = None

    @field_validator("rule_id_match")
    @classmethod
    def _valid_regex(cls, v: Optional[str]) -> Optional[str]:
        if v is None:
            return v
        try:
            re.compile(v)
        except re.error as e:
            raise ValueError(f"invalid rule_id_match regex: {e}") from e
        return v


class ChainPredicate(BaseModel):
    """One `all_of` entry inside a chain rule."""

    finding: Optional[FindingPredicate] = None
    # Or a predicate on an asset directly — used for chains that fire on
    # the presence of a non-finding node (e.g. a secret_candidate asset).
    asset: Optional[dict[str, Any]] = None
    scope: Scope = "same_host"

    @field_validator("asset")
    @classmethod
    def _asset_kind_required(
        cls, v: Optional[dict[str, Any]]
    ) -> Optional[dict[str, Any]]:
        if v is not None and "kind" not in v:
            raise ValueError("asset predicate requires 'kind'")
        return v


class ChainRule(BaseModel):
    id: str
    name: str
    severity: Severity
    window_days: int = Field(default=30, ge=1, le=3650)
    all_of: list[ChainPredicate] = Field(min_length=2)
    any_of: list[ChainPredicate] = Field(default_factory=list)
    impact: str = ""
    remediation: list[str] = Field(default_factory=list)
    references: list[str] = Field(default_factory=list)
    # Where the rule came from on disk — populated by the loader.
    source_path: Optional[str] = None

    @field_validator("id")
    @classmethod
    def _id_ok(cls, v: str) -> str:
        if not re.fullmatch(r"[a-z0-9][a-z0-9_\-]{2,63}", v):
            raise ValueError(
                "id must be 3-64 chars of [a-z0-9_-], starting alnum"
            )
        return v


class PolicyScope(BaseModel):
    asset_tag: Optional[str] = None
    asset_kind: Optional[str] = None


class PolicyOnHit(BaseModel):
    create_finding: dict[str, Any] = Field(default_factory=dict)


class PolicyRule(BaseModel):
    id: str
    name: str
    severity: Severity
    scope: PolicyScope = Field(default_factory=PolicyScope)
    query: str
    on_hit: PolicyOnHit
    description: str = ""
    remediation: list[str] = Field(default_factory=list)
    source_path: Optional[str] = None

    @field_validator("id")
    @classmethod
    def _id_ok(cls, v: str) -> str:
        if not re.fullmatch(r"[a-z0-9][a-z0-9_\-]{2,63}", v):
            raise ValueError("invalid policy id")
        return v


# ----------------------------------------------------------------------------
# Loader
# ----------------------------------------------------------------------------

class RuleLoader:
    """Loads chain and policy YAMLs from one or more directories.

    `builtin_dir` ships with the image; `overlay_dir` is the mounted
    `/policies` volume. Files in the overlay with the same filename
    replace builtin ones."""

    def __init__(
        self,
        builtin_dir: Optional[str] = None,
        overlay_dir: Optional[str] = None,
    ) -> None:
        self.builtin_dir = Path(builtin_dir) if builtin_dir else None
        self.overlay_dir = Path(overlay_dir) if overlay_dir else None
        self.chains: dict[str, ChainRule] = {}
        self.policies: dict[str, PolicyRule] = {}
        self.errors: list[dict[str, str]] = []

    # One place to resolve "builtin + overlay".
    def _iter_yaml_files(self) -> list[Path]:
        seen: dict[str, Path] = {}
        for base in (self.builtin_dir, self.overlay_dir):
            if base is None or not base.exists():
                continue
            for p in sorted(base.rglob("*.y*ml")):
                rel_parts = p.relative_to(base).parts
                # The `attack/` subtree holds ATT&CK technique maps, not
                # chain/policy rules; it is owned by engine.attack_mapping
                # and must not be parsed here.
                if any(part.lower() in _NON_RULE_DIRS for part in rel_parts):
                    continue
                # key by filename relative to the base, so overlay/chains/foo.yaml
                # replaces builtin/chains/foo.yaml.
                rel = str(p.relative_to(base))
                seen[rel] = p
        return list(seen.values())

    def load_all(self) -> None:
        self.chains.clear()
        self.policies.clear()
        self.errors.clear()

        for path in self._iter_yaml_files():
            try:
                self._load_one(path)
            except (UnsafeRuleError, ValidationError, yaml.YAMLError) as e:
                self.errors.append({"path": str(path), "error": str(e)})
                log.warning(
                    "rule %s rejected: %s", path, e
                )
            except Exception as e:  # pragma: no cover - defensive
                self.errors.append({"path": str(path), "error": str(e)})
                log.exception("rule %s crashed loader", path)

    def _load_one(self, path: Path) -> None:
        text = path.read_text(encoding="utf-8")
        doc = yaml.safe_load(text)
        if not isinstance(doc, dict):
            raise UnsafeRuleError(
                "top-level YAML must be a mapping"
            )

        _check_forbidden_keys(doc, str(path))

        kind = self._guess_kind(doc, path)

        if kind == "chain":
            rule = ChainRule(**doc)
            rule.source_path = str(path)
            validate_narrative_text(rule.impact)
            for r in rule.remediation:
                validate_narrative_text(r)
            if rule.id in self.chains:
                log.info(
                    "chain %s overridden by %s", rule.id, path
                )
            self.chains[rule.id] = rule
        elif kind == "policy":
            rule = PolicyRule(**doc)
            rule.source_path = str(path)
            validate_narrative_text(rule.description)
            validate_sql(rule.query)
            if rule.id in self.policies:
                log.info(
                    "policy %s overridden by %s", rule.id, path
                )
            self.policies[rule.id] = rule
        else:
            raise UnsafeRuleError(
                f"cannot determine rule kind (chain|policy) for {path}"
            )

    @staticmethod
    def _guess_kind(doc: dict[str, Any], path: Path) -> str:
        if "all_of" in doc or "any_of" in doc:
            return "chain"
        if "query" in doc:
            return "policy"
        # Fallback: directory name.
        parts = {p.lower() for p in path.parts}
        if "chains" in parts:
            return "chain"
        if "policies" in parts:
            return "policy"
        return "unknown"

    # -- debug --------------------------------------------------------------

    def summary(self) -> dict[str, Any]:
        return {
            "chains": [
                {
                    "id": r.id,
                    "name": r.name,
                    "severity": r.severity,
                    "predicates": len(r.all_of),
                    "source": r.source_path,
                }
                for r in self.chains.values()
            ],
            "policies": [
                {
                    "id": r.id,
                    "name": r.name,
                    "severity": r.severity,
                    "source": r.source_path,
                }
                for r in self.policies.values()
            ],
            "errors": list(self.errors),
        }

    # -- used by the file-watcher -------------------------------------------

    def watched_paths(self) -> list[str]:
        out = []
        for base in (self.builtin_dir, self.overlay_dir):
            if base is not None and base.exists():
                out.append(str(base))
        return out


# ----------------------------------------------------------------------------
# Finding → predicate match (pure python, for use after the DB query filters
# already narrowed things down).
# ----------------------------------------------------------------------------

_SEVERITY_RANK = {
    "info": 0,
    "low": 1,
    "medium": 2,
    "high": 3,
    "critical": 4,
}


def finding_matches(pred: FindingPredicate, finding: dict[str, Any]) -> bool:
    """Check all optional fields on the predicate against a finding row."""
    if pred.rule_source and finding.get("rule_source") != pred.rule_source:
        return False
    if pred.rule_id and finding.get("rule_id") != pred.rule_id:
        return False
    if pred.rule_id_match and not re.search(
        pred.rule_id_match, finding.get("rule_id", "") or ""
    ):
        return False
    if pred.severity_min:
        sev = finding.get("severity", "info")
        if _SEVERITY_RANK.get(sev, -1) < _SEVERITY_RANK[pred.severity_min]:
            return False
    if pred.cvss_min is not None:
        cvss = finding.get("cvss")
        if cvss is None or float(cvss) < pred.cvss_min:
            return False
    if pred.epss_min is not None:
        epss = finding.get("epss")
        if epss is None or float(epss) < pred.epss_min:
            return False
    if pred.known_exploited is not None:
        md = finding.get("metadata") or {}
        kev = bool(md.get("kev") or md.get("known_exploited"))
        if kev != pred.known_exploited:
            return False
    if pred.status:
        # Missing status is treated as 'open' — findings default open.
        actual = finding.get("status") or "open"
        if actual != pred.status:
            return False
    if pred.evidence:
        ev = finding.get("evidence") or {}
        for k, v in pred.evidence.items():
            if ev.get(k) != v:
                return False
    if pred.metadata:
        md = finding.get("metadata") or {}
        for k, v in pred.metadata.items():
            if md.get(k) != v:
                return False
    return True


def asset_matches(pred: dict[str, Any], asset: dict[str, Any]) -> bool:
    """Check an asset-predicate against an asset row."""
    for k, v in pred.items():
        if k == "metadata":
            md = asset.get("metadata") or {}
            for mk, mv in (v or {}).items():
                if md.get(mk) != mv:
                    return False
        elif k == "value_match":
            if not re.search(v, asset.get("value", "") or ""):
                return False
        else:
            if asset.get(k) != v:
                return False
    return True


def rule_file_glob(roots: list[str]) -> list[str]:
    patterns = []
    for root in roots:
        patterns.append(os.path.join(root, "**", "*.yaml"))
        patterns.append(os.path.join(root, "**", "*.yml"))
    return patterns
