"""The shipped ``std:*`` invariants. Canonical definitions that consumers can require by id."""
from __future__ import annotations

from importlib import resources

from ..compile import Plan, compile_text


def list_std() -> list[str]:
    names = sorted(p.name[:-5] for p in resources.files(__package__).iterdir()
                   if p.name.endswith(".yaml"))
    return [f"std:{n}" for n in names]


def std_text(invariant_id: str) -> str:
    if not invariant_id.startswith("std:"):
        raise KeyError(invariant_id)
    name = invariant_id[4:]
    if not name or "/" in name or ".." in name:
        raise KeyError(invariant_id)
    f = resources.files(__package__).joinpath(f"{name}.yaml")
    if not f.is_file():
        raise KeyError(invariant_id)
    return f.read_text(encoding="utf-8")


def load_std(invariant_id: str) -> Plan:
    plan = compile_text(std_text(invariant_id))
    if plan.id != invariant_id:
        raise ValueError(f"{invariant_id}: file declares id {plan.id!r}")
    return plan
