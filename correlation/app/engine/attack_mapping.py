"""MITRE ATT&CK + CWE mapping for findings.

Tags each open finding with the ATT&CK technique(s) / tactic(s) / weakness
it represents, so findings roll up into an ATT&CK coverage view.

Three pieces:

* A YAML-backed rule catalog (`correlation/app/rules/attack/technique_map.yaml`),
  loaded and validated with pydantic. The same safety gates the chain/policy
  loader uses apply: a forbidden key (`exploit`, `payload`, `shell`, ...)
  anywhere rejects the whole file, and any rule whose text reads like an
  exploitation guide (via `validate_narrative_text`) is logged and skipped.
  This is classification metadata only — it never describes how to attack.

* `AttackMapper.sync_catalog()` idempotently upserts the loaded rules into
  `attack_technique_map` so the orchestrator/dashboard can read the catalog.

* `AttackMapper.map_findings()` evaluates the rules against every open
  finding (bulk-load, bulk-write; no N+1) and upserts `finding_techniques`.
  `AttackMapper.coverage()` aggregates per-technique / per-tactic counts.

Rule evaluation is deterministic: rules are sorted by (priority, id); for a
given finding the first rule per `technique_id` wins, but a finding may carry
several techniques when rules match different `technique_id`s.

All SQL is parameterized asyncpg.
"""
from __future__ import annotations

import logging
import re
import time
import uuid
from pathlib import Path
from typing import Any, Optional

import yaml
from pydantic import BaseModel, Field, ValidationError, field_validator, model_validator

from ..db import Database
from .policy import (
    UnsafeRuleError,
    _check_forbidden_keys,
    validate_narrative_text,
)

log = logging.getLogger(__name__)

# Stable namespace so a rule id always maps to the same catalog row id,
# which makes the catalog upsert idempotent.
_CATALOG_NS = uuid.UUID("6f1d3c2a-0a7e-5f4b-9c2d-1e8a4b6c7d90")

_TECHNIQUE_RE = re.compile(r"^T\d{4}(?:\.\d{3})?$")
_CWE_RE = re.compile(r"^CWE-\d+$")
_ID_RE = re.compile(r"^[a-z0-9][a-z0-9_\-]{2,63}$")


# ----------------------------------------------------------------------------
# Pydantic models for the YAML DSL
# ----------------------------------------------------------------------------

class AttackMatch(BaseModel):
    """Match predicate against a finding row. All fields optional, AND-ed,
    but at least one must be set so a rule can never match everything."""

    rule_source: Optional[str] = None
    rule_id_regex: Optional[str] = None
    title_regex: Optional[str] = None

    @field_validator("rule_id_regex", "title_regex")
    @classmethod
    def _valid_regex(cls, v: Optional[str]) -> Optional[str]:
        if v is None:
            return v
        try:
            re.compile(v)
        except re.error as e:
            raise ValueError(f"invalid regex: {e}") from e
        return v

    @model_validator(mode="after")
    def _at_least_one(self) -> "AttackMatch":
        if not (self.rule_source or self.rule_id_regex or self.title_regex):
            raise ValueError(
                "match must set at least one of "
                "rule_source / rule_id_regex / title_regex"
            )
        return self


class AttackMapRule(BaseModel):
    id: str
    match: AttackMatch
    technique_id: str
    technique: str
    tactic: str
    cwe: Optional[str] = None
    priority: int = Field(default=100, ge=0, le=10000)
    confidence: int = Field(default=80, ge=0, le=100)
    enabled: bool = True

    @field_validator("id")
    @classmethod
    def _id_ok(cls, v: str) -> str:
        if not _ID_RE.fullmatch(v):
            raise ValueError("id must be 3-64 chars of [a-z0-9_-], starting alnum")
        return v

    @field_validator("technique_id")
    @classmethod
    def _tech_ok(cls, v: str) -> str:
        if not _TECHNIQUE_RE.fullmatch(v):
            raise ValueError(f"technique_id must look like Txxxx[.nnn]; got {v!r}")
        return v

    @field_validator("cwe")
    @classmethod
    def _cwe_ok(cls, v: Optional[str]) -> Optional[str]:
        if v is not None and not _CWE_RE.fullmatch(v):
            raise ValueError(f"cwe must look like CWE-<n>; got {v!r}")
        return v

    @field_validator("technique", "tactic")
    @classmethod
    def _nonempty(cls, v: str) -> str:
        if not v or not v.strip():
            raise ValueError("must be non-empty")
        return v

    def catalog_id(self) -> str:
        return str(uuid.uuid5(_CATALOG_NS, self.id))

    def match_dict(self) -> dict[str, Any]:
        """The JSONB `match` payload stored in attack_technique_map."""
        out: dict[str, Any] = {}
        if self.match.rule_source is not None:
            out["rule_source"] = self.match.rule_source
        if self.match.rule_id_regex is not None:
            out["rule_id_regex"] = self.match.rule_id_regex
        if self.match.title_regex is not None:
            out["title_regex"] = self.match.title_regex
        return out


# ----------------------------------------------------------------------------
# Pure matching helpers (unit-testable without a database)
# ----------------------------------------------------------------------------

def rule_matches(rule: AttackMapRule, finding: dict[str, Any]) -> bool:
    """True if every set field of the rule's match predicate holds."""
    m = rule.match
    if m.rule_source is not None and finding.get("rule_source") != m.rule_source:
        return False
    if m.rule_id_regex is not None and not re.search(
        m.rule_id_regex, finding.get("rule_id") or ""
    ):
        return False
    if m.title_regex is not None and not re.search(
        m.title_regex, finding.get("title") or ""
    ):
        return False
    return True


def techniques_for_finding(
    rules: list[AttackMapRule], finding: dict[str, Any]
) -> list[AttackMapRule]:
    """Evaluate rules priority ASC (then id); keep the first rule per
    technique_id. A finding can thus carry several techniques, de-duplicated
    by technique_id."""
    chosen: dict[str, AttackMapRule] = {}
    for rule in sorted(rules, key=lambda r: (r.priority, r.id)):
        if not rule.enabled:
            continue
        if rule.technique_id in chosen:
            continue
        if rule_matches(rule, finding):
            chosen[rule.technique_id] = rule
    # Deterministic output order: by priority then technique_id.
    return sorted(chosen.values(), key=lambda r: (r.priority, r.technique_id))


# ----------------------------------------------------------------------------
# Loader
# ----------------------------------------------------------------------------

class AttackMapLoader:
    """Loads + validates the ATT&CK technique-map YAML.

    A forbidden key anywhere in the document rejects the whole file (so a
    `payload:`/`exploit:` block can't ride along). Individual rules that fail
    pydantic validation or whose text reads like exploitation guidance are
    logged and skipped."""

    def __init__(self, path: str) -> None:
        self.path = Path(path)
        self.rules: list[AttackMapRule] = []
        self.errors: list[dict[str, str]] = []

    def load(self) -> None:
        self.rules = []
        self.errors = []
        if not self.path.exists():
            self.errors.append({"path": str(self.path), "error": "file not found"})
            log.warning("attack technique_map not found at %s", self.path)
            return
        try:
            text = self.path.read_text(encoding="utf-8")
            doc = yaml.safe_load(text)
        except (yaml.YAMLError, OSError) as e:
            self.errors.append({"path": str(self.path), "error": str(e)})
            log.warning("attack technique_map unreadable: %s", e)
            return

        if not isinstance(doc, dict):
            self.errors.append(
                {"path": str(self.path), "error": "top-level YAML must be a mapping"}
            )
            return

        # Whole-file safety gate: forbidden keys (exploit/payload/shell/...).
        try:
            _check_forbidden_keys(doc, str(self.path))
        except UnsafeRuleError as e:
            self.errors.append({"path": str(self.path), "error": str(e)})
            log.warning("attack technique_map rejected: %s", e)
            return

        raw_rules = doc.get("rules")
        if not isinstance(raw_rules, list):
            self.errors.append(
                {"path": str(self.path), "error": "'rules' must be a list"}
            )
            return

        seen_ids: set[str] = set()
        for i, raw in enumerate(raw_rules):
            ref = f"rule[{i}]"
            try:
                if not isinstance(raw, dict):
                    raise UnsafeRuleError("rule must be a mapping")
                # Per-rule narrative gate: text fields must read as labels,
                # not exploitation steps.
                for fld in ("technique", "tactic", "cwe"):
                    val = raw.get(fld)
                    if isinstance(val, str):
                        validate_narrative_text(val)
                rule = AttackMapRule(**raw)
                if rule.id in seen_ids:
                    raise UnsafeRuleError(f"duplicate rule id {rule.id!r}")
                seen_ids.add(rule.id)
                self.rules.append(rule)
            except (ValidationError, UnsafeRuleError, ValueError) as e:
                rid = raw.get("id") if isinstance(raw, dict) else None
                self.errors.append(
                    {"path": f"{self.path}:{rid or ref}", "error": str(e)}
                )
                log.warning("attack rule %s rejected: %s", rid or ref, e)

    def summary(self) -> dict[str, Any]:
        return {
            "count": len(self.rules),
            "rules": [
                {
                    "id": r.id,
                    "technique_id": r.technique_id,
                    "tactic": r.tactic,
                    "cwe": r.cwe,
                    "priority": r.priority,
                }
                for r in self.rules
            ],
            "errors": list(self.errors),
        }


# ----------------------------------------------------------------------------
# Mapper (DB-backed)
# ----------------------------------------------------------------------------

class AttackMapper:
    def __init__(self, db: Database, rules: list[AttackMapRule]) -> None:
        self._db = db
        self._rules = list(rules)

    @property
    def rules(self) -> list[AttackMapRule]:
        return self._rules

    def set_rules(self, rules: list[AttackMapRule]) -> None:
        self._rules = list(rules)

    # -- catalog ------------------------------------------------------------

    async def sync_catalog(self) -> int:
        """Idempotently upsert the loaded rules into attack_technique_map.

        The row id is derived from the rule id (uuid5), so repeated syncs
        update in place rather than inserting duplicates. Returns the number
        of rules written."""
        if not self._rules:
            return 0
        ids: list[str] = []
        matches: list[dict[str, Any]] = []
        tech_ids: list[str] = []
        techs: list[str] = []
        tactics: list[str] = []
        cwes: list[Optional[str]] = []
        priorities: list[int] = []
        enabled: list[bool] = []
        for r in self._rules:
            ids.append(r.catalog_id())
            matches.append(r.match_dict())
            tech_ids.append(r.technique_id)
            techs.append(r.technique)
            tactics.append(r.tactic)
            cwes.append(r.cwe)
            priorities.append(r.priority)
            enabled.append(r.enabled)

        async with self._db.acquire() as conn:
            async with conn.transaction():
                await conn.execute(
                    """
                    INSERT INTO attack_technique_map (
                      id, match, technique_id, technique, tactic, cwe,
                      priority, enabled
                    )
                    SELECT * FROM unnest(
                      $1::uuid[], $2::jsonb[], $3::text[], $4::text[],
                      $5::text[], $6::text[], $7::smallint[], $8::boolean[]
                    )
                    ON CONFLICT (id) DO UPDATE SET
                      match        = EXCLUDED.match,
                      technique_id = EXCLUDED.technique_id,
                      technique    = EXCLUDED.technique,
                      tactic       = EXCLUDED.tactic,
                      cwe          = EXCLUDED.cwe,
                      priority     = EXCLUDED.priority,
                      enabled      = EXCLUDED.enabled
                    """,
                    ids,
                    matches,
                    tech_ids,
                    techs,
                    tactics,
                    cwes,
                    priorities,
                    enabled,
                )
        return len(self._rules)

    # -- mapping ------------------------------------------------------------

    @staticmethod
    def _rows_for(
        rules: list[AttackMapRule], finding: dict[str, Any]
    ) -> list[tuple[str, str, str, str, Optional[str], int]]:
        """Build (finding_id, technique_id, technique, tactic, cwe, confidence)
        rows for one finding."""
        fid = str(finding["id"])
        out = []
        for r in techniques_for_finding(rules, finding):
            out.append(
                (fid, r.technique_id, r.technique, r.tactic, r.cwe, r.confidence)
            )
        return out

    async def _bulk_upsert(
        self, rows: list[tuple[str, str, str, str, Optional[str], int]]
    ) -> None:
        if not rows:
            return
        fids = [r[0] for r in rows]
        tech_ids = [r[1] for r in rows]
        techs = [r[2] for r in rows]
        tactics = [r[3] for r in rows]
        cwes = [r[4] for r in rows]
        confs = [r[5] for r in rows]
        async with self._db.acquire() as conn:
            async with conn.transaction():
                await conn.execute(
                    """
                    INSERT INTO finding_techniques (
                      finding_id, technique_id, technique, tactic, cwe, confidence
                    )
                    SELECT * FROM unnest(
                      $1::uuid[], $2::text[], $3::text[], $4::text[],
                      $5::text[], $6::smallint[]
                    )
                    ON CONFLICT (finding_id, technique_id) DO UPDATE SET
                      technique  = EXCLUDED.technique,
                      tactic     = EXCLUDED.tactic,
                      cwe        = EXCLUDED.cwe,
                      confidence = EXCLUDED.confidence,
                      mapped_at  = NOW()
                    """,
                    fids,
                    tech_ids,
                    techs,
                    tactics,
                    cwes,
                    confs,
                )

    async def map_findings(self, limit: int = 20000) -> dict[str, Any]:
        """Map every open finding. Bulk-load findings, evaluate in Python,
        bulk-upsert finding_techniques. Returns a summary."""
        started = time.monotonic()
        if not self._rules:
            return {
                "mapped": 0,
                "techniques": 0,
                "tactics": 0,
                "elapsed_ms": 0.0,
            }
        rows = await self._db.fetch(
            """
            SELECT id::text AS id, rule_id, rule_source, title
            FROM findings
            WHERE status = 'open'
            ORDER BY last_seen DESC
            LIMIT $1
            """,
            limit,
        )
        upserts: list[tuple[str, str, str, str, Optional[str], int]] = []
        mapped_findings = 0
        for r in rows:
            frows = self._rows_for(self._rules, dict(r))
            if frows:
                mapped_findings += 1
                upserts.extend(frows)
        await self._bulk_upsert(upserts)
        techniques = {u[1] for u in upserts}
        tactics = {u[3] for u in upserts}
        elapsed_ms = round((time.monotonic() - started) * 1000.0, 2)
        log.info(
            "attack map: %d findings mapped, %d techniques, %d tactics in %.1fms",
            mapped_findings,
            len(techniques),
            len(tactics),
            elapsed_ms,
        )
        return {
            "mapped": mapped_findings,
            "techniques": len(techniques),
            "tactics": len(tactics),
            "elapsed_ms": elapsed_ms,
        }

    async def map_finding(self, finding_id: str) -> int:
        """Map a single finding (used on finding_opened). Returns the number
        of techniques written."""
        if not self._rules:
            return 0
        row = await self._db.fetchrow(
            """
            SELECT id::text AS id, rule_id, rule_source, title
            FROM findings
            WHERE id = $1::uuid AND status = 'open'
            """,
            finding_id,
        )
        if row is None:
            return 0
        rows = self._rows_for(self._rules, dict(row))
        await self._bulk_upsert(rows)
        return len(rows)

    # -- coverage -----------------------------------------------------------

    async def coverage(self) -> dict[str, Any]:
        """Aggregate the current ATT&CK coverage.

        Counts are DISTINCT findings, so a finding carrying two techniques in
        the same tactic is counted once per tactic. Returns:
          {by_tactic: {tactic: count}, by_technique: [{id,technique,tactic,count}],
           total: distinct findings mapped}
        """
        tech_rows = await self._db.fetch(
            """
            SELECT technique_id, technique, tactic,
                   COUNT(DISTINCT finding_id) AS count
            FROM finding_techniques
            GROUP BY technique_id, technique, tactic
            ORDER BY count DESC, technique_id ASC
            """
        )
        tactic_rows = await self._db.fetch(
            """
            SELECT tactic, COUNT(DISTINCT finding_id) AS count
            FROM finding_techniques
            GROUP BY tactic
            ORDER BY count DESC, tactic ASC
            """
        )
        total = await self._db.fetchval(
            "SELECT COUNT(DISTINCT finding_id) FROM finding_techniques"
        )
        return {
            "by_tactic": {r["tactic"]: int(r["count"]) for r in tactic_rows},
            "by_technique": [
                {
                    "id": r["technique_id"],
                    "technique": r["technique"],
                    "tactic": r["tactic"],
                    "count": int(r["count"]),
                }
                for r in tech_rows
            ],
            "total": int(total or 0),
        }


def default_rules_path(builtin_rules_dir: str) -> str:
    """The bundled technique_map.yaml under the rules root."""
    return str(Path(builtin_rules_dir) / "attack" / "technique_map.yaml")
