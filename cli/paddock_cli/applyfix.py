"""Apply accepted fix plans to disk and prove they worked by re-running the checks."""
from __future__ import annotations

import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from .fixplan import FixPlan, combined_edits
from .model import ScanResult
from .osvclient import key_of


class ApplyError(RuntimeError):
    pass


def _norm_eol(text: str) -> str:
    return text.replace("\r\n", "\n")


def check_clean(plans: list[FixPlan], root: Path) -> None:
    """Refuse to write if a file differs from what the plan was computed against."""
    for path, (before, _after) in combined_edits(plans).items():
        p = root / path
        if before is None:
            if p.exists():
                raise ApplyError(f"{path} appeared since the scan; re-run `paddock fix`")
            continue
        try:
            now = p.read_text(encoding="utf-8")
        except OSError as exc:
            raise ApplyError(f"cannot read {path}: {exc}") from exc
        if _norm_eol(now).rstrip("\n") != _norm_eol(before).rstrip("\n"):
            raise ApplyError(f"{path} changed since the scan; re-run `paddock fix`")


def apply_plans(plans: list[FixPlan], root: str | Path) -> list[str]:
    root = Path(root).resolve()
    check_clean(plans, root)
    written = []
    for path, (_before, after) in sorted(combined_edits(plans).items()):
        dest = (root / path).resolve()
        if root not in dest.parents:           # never write outside the scanned tree
            raise ApplyError(f"refusing to write outside the repo: {path}")
        dest.parent.mkdir(parents=True, exist_ok=True)
        tmp = dest.with_name(f".{dest.name}.paddock-{os.getpid()}")
        tmp.write_bytes(after.encode("utf-8"))
        try:
            os.chmod(tmp, dest.stat().st_mode & 0o7777)
        except OSError:
            pass
        os.replace(tmp, dest)
        written.append(path)
    return written


@dataclass
class Outcome:
    plan: FixPlan
    status: str                 # fixed | still_present | unverified
    reason: str = ""


@dataclass
class Verification:
    outcomes: list[Outcome] = field(default_factory=list)

    @property
    def total(self) -> int:
        return len(self.outcomes)

    @property
    def fixed(self) -> int:
        return sum(1 for o in self.outcomes if o.status == "fixed")

    def as_dict(self) -> dict[str, Any]:
        return {"fixed": self.fixed, "total": self.total,
                "fixes": [{"id": o.plan.id, "title": o.plan.title, "status": o.status,
                           "reason": o.reason} for o in self.outcomes]}


def verify_plans(plans: list[FixPlan], after: ScanResult) -> Verification:
    """Compare a fresh scan with the fixes that were applied.

    A fix counts only when the findings it targeted are gone *and* (for a dependency) no
    finding remains for that package in that file at the new version either.
    """
    remaining_ids = {f.id for f in after.findings}
    dep_left = {(f.data.get("ecosystem"), f.data.get("package"), f.file)
                for f in after.findings if f.kind in ("dependency", "malicious")}
    unchecked = set(after.stats.get("osv_unchecked_keys") or [])
    out = Verification()
    for p in plans:
        if any(r in remaining_ids for r in p.resolves):
            out.outcomes.append(Outcome(p, "still_present", "the scan still reports it"))
            continue
        if p.kind == "dependency":
            d = p.detail
            f = d["file"]
            if (d["ecosystem"], d["package"], f) in dep_left:
                out.outcomes.append(Outcome(
                    p, "still_present", f"{d['package']} {d['to']} is itself reported vulnerable"))
                continue
            if key_of(d["ecosystem"], d["package"], d["to"]) in unchecked:
                out.outcomes.append(Outcome(
                    p, "unverified", f"{d['to']} could not be checked against OSV (offline cache)"))
                continue
        out.outcomes.append(Outcome(p, "fixed"))
    return out
