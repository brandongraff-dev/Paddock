# SPDX-License-Identifier: AGPL-3.0-or-later
"""Facade used by the CLI commands and by the MCP server (contract 3.3).

``check``, ``explain`` and ``list_checks`` return JSON-safe dicts. ``check`` writes nothing by
default (``no_cache=True``): a read-only handoff. ``run_scan`` is the single place a scan is
assembled (config, context, engine) so every command behaves the same way.
"""
from __future__ import annotations

import os
from dataclasses import dataclass
from typing import Any, Iterable, Mapping, Sequence

from paddock_cli.guard import GUARD_VERSION, config, context, engine, files, fixers, model, output, registry, textsafe
from paddock_cli.guard.errors import UsageError
from paddock_cli.guard.model import Report


@dataclass
class ScanResult:
    report: Report
    cfg: config.Config
    state_dir: str | None


def split_only(values: Iterable[str] | None) -> list[str] | None:
    if not values:
        return None
    out: list[str] = []
    for v in values:
        out += [p.strip() for p in str(v).split(",") if p.strip()]
    return out or None


def run_scan(root: str, *, tier: str | None = None, fail_on: str | None = None, only: Iterable[str] | None = None,
             changed: bool | Sequence[str] = False, base: str | None = None, staged: bool = False,
             offline: bool = False, config_ref: str | None = None, baseline_ref: str | None = None,
             use_baseline: bool = True, no_cache: bool = False, deadline: float | None = None,
             hook_mode: bool = False, extra_cli: Mapping[str, Any] | None = None) -> ScanResult:
    """Load the config, open the context, run the engine. Raises ``GuardError`` subclasses."""
    cli_opts: dict[str, Any] = {"tier": tier, "fail_on": fail_on, "offline": offline}
    if extra_cli:
        cli_opts.update(extra_cli)
    cfg = config.load_config(root, cli=cli_opts, config_ref=config_ref, hook_mode=hook_mode)
    with context.ScanContext.open(root, cfg, base=base, staged=staged, offline=offline, no_state=no_cache) as ctx:
        changed_list: list[str] | None = None
        if changed is True:
            changed_list = ctx.changed_files()
            if changed_list is None:
                ctx.add_note("git-unavailable: --changed needs a git work tree; every file was scanned")
        elif isinstance(changed, (list, tuple)):
            changed_list = list(changed)
        report = engine.run_checks(ctx, tier=cfg.tier, only=split_only(only), changed=changed_list,
                                   baseline_ref=baseline_ref, use_baseline=use_baseline, deadline=deadline)
        state = ctx.state_dir
    return ScanResult(report, cfg, state)


def check(root: str, **opts: Any) -> dict[str, Any]:
    """Run a check and return the report as a JSON-safe dict (nothing is written by default)."""
    opts.setdefault("no_cache", True)
    return output.report_dict(run_scan(root, **opts).report)


def _check_info(c: registry.Check) -> dict[str, Any]:
    eff, label = registry.effective_tier(c)
    return {
        "id": c.id, "title": textsafe.safe_text(c.title, cap=200, escape=False), "pack": c.pack, "severity": c.severity,
        "declared_tier": c.proposed_tier, "effective_tier": eff, "tier_evidence": label, "scope": c.scope,
    }


def explain(check_id: str) -> dict[str, Any]:
    registry.discover()
    c = registry.get(check_id)
    d = _check_info(c)
    d.update({
        "why": textsafe.safe_text(registry.why_text(c), cap=1200, escape=False),
        "fix_hint": textsafe.safe_text(c.fix_hint, cap=1200, escape=False),
        "agent_prompt_template": textsafe.cap(textsafe.clean(c.agent_prompt, keep_newlines=True), 1200),
        "cwe": c.cwe, "refs": [textsafe.safe_text(r, cap=200, escape=False) for r in c.refs], "fixer": c.fixer,
        "fixer_breaking": bool(c.fixer and c.fixer in fixers.BREAKING),
        "inline_suppressible": c.inline_suppressible, "spec_status": c.spec_status,
        "unverified_ids": list(c.unverified_ids), "open_unverified_ids": registry.open_unverified(c),
        "network": c.network, "globs": list(c.globs), "origin": c.origin,
    })
    return d


def list_checks(tier: str | None = None) -> list[dict[str, Any]]:
    """Every check; with ``tier`` only those that run at that tier (effective tier at or above it)."""
    registry.discover()
    if tier is not None and tier not in model.TIERS:
        raise UsageError("unknown tier")
    out = []
    for c in registry.all_checks():
        info = _check_info(c)
        if tier is None or model.tier_rank(info["effective_tier"]) >= model.tier_rank(tier):
            out.append(info)
    return out


def status(root: str = ".", *, env: Mapping[str, str] | None = None) -> dict[str, Any]:
    """Facts for ``paddock guard status``: version, check counts, config trust, state, ledger."""
    from paddock_cli.guard import ledger as ledger_mod

    registry.discover()
    e = os.environ if env is None else env
    checks = registry.all_checks()
    by_eff: dict[str, int] = {"high": 0, "medium": 0, "low": 0}
    for c in checks:
        by_eff[registry.effective_tier(c)[0]] += 1
    root_real = files.real_root(root)
    path, env_dir = config.user_config_location(e)
    present = bool(path and os.path.lexists(path))
    trusted = present and not config.user_config_trust(path, env_dir, root_real)  # type: ignore[arg-type]
    state = files.state_dir(root_real, create=False)
    exists = bool(state and os.path.isdir(state))
    events = len(ledger_mod.Ledger(state).read()) if exists else 0
    return {
        "version": GUARD_VERSION, "release_build": model.REQUIRE_TIERS,
        "checks": {"total": len(checks), "effective_high": by_eff["high"], "effective_medium": by_eff["medium"],
                   "effective_low": by_eff["low"]},
        "tiers_json_present": bool(registry.load_tiers()), "verified_ids": len(registry.load_verified()),
        "user_config": {"present": present, "trusted": trusted},
        "project_config": os.path.isfile(os.path.join(root_real, ".paddock", "guard.toml")),
        "baseline": os.path.isfile(os.path.join(root_real, ".paddock", "baseline.json")),
        "state_dir_exists": exists, "ledger_events": events,
        "import_errors": [m for m, _ in registry.import_errors()],
    }
