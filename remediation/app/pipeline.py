"""The remediation pipeline — wires all six guardrail layers together.

Per finding:
  select change class
    -> injection scan on the finding's own fields       (LAYER 5, early)
    -> resolve DB-authoritative parameters              (LAYER 2 inputs)
    -> generate the diff DETERMINISTICALLY               (LAYER 2)
    -> deterministic diff gate                           (LAYER 3)
    -> build PR title/body + optional LLM explanation    (LAYER 1 isolation)
    -> injection scan on the PR title/body               (LAYER 5)
    -> adversarial verify (rule + optional LLM)          (LAYER 4)
    -> if ALL pass: status 'verified'; optionally open a PROPOSED PR  (LAYER 6)
       else: status 'rejected' with the reason

Every attempt is persisted to ``remediations`` with the diff + the gate /
verifier / injection reports. NOTHING is ever auto-merged. The LLM never emits
a diff; its absence cannot weaken the gate.
"""
from __future__ import annotations

import logging
from typing import Any

from . import gate as gate_mod
from . import generators as gen
from . import github as gh
from . import injection
from . import verify as verify_mod
from .config import Config
from .db import now

log = logging.getLogger("remediation.pipeline")

VALID_KINDS = {"dependency_bump", "security_header", "config_fix", "tls_fix", "dotfile_block"}

# finding.rule_source -> change class.
_SOURCE_TO_CLASS: dict[str, str] = {
    "sca": "dependency_bump",
    "cve_match": "dependency_bump",
    "header_check": "security_header",
    "tls_check": "config_fix",
    "tls_grade": "config_fix",
    "exposed_file": "dotfile_block",
}


def select_change_class(finding: dict[str, Any]) -> str | None:
    """Pick the allowlisted change class for a finding. An explicit
    ``metadata.remediation_kind`` wins (if valid); else map by rule_source; else
    sniff an exposed-/.git finding."""
    meta = finding.get("metadata") or {}
    if isinstance(meta, dict):
        override = meta.get("remediation_kind")
        if override in VALID_KINDS:
            return override
    rs = str(finding.get("rule_source") or "")
    if rs in _SOURCE_TO_CLASS:
        return _SOURCE_TO_CLASS[rs]
    blob = f"{finding.get('rule_id','')} {finding.get('title','')}".lower()
    if "/.git" in blob or "git-exposed" in blob or "exposed .git" in blob:
        return "dotfile_block"
    return None


class Pipeline:
    def __init__(self, db: Any, llm: Any, cfg: Config) -> None:
        self.db = db
        self.llm = llm
        self.cfg = cfg

    async def propose(self, finding_id: str, created_by: str = "remediation") -> dict[str, Any]:
        finding = await self.db.get_finding(finding_id)
        if finding is None:
            return {"ok": False, "error": "finding_not_found", "finding_id": finding_id}

        change_class = select_change_class(finding)
        if change_class is None:
            return {
                "ok": False, "status": "skipped",
                "error": "no_applicable_change_class",
                "finding_id": finding_id,
                "note": "no allowlisted change class maps to this finding",
            }

        # LAYER 5 (early): scan the finding's OWN fields. A malicious finding is
        # refused here — before we generate anything and before any PR — and the
        # injection flag is recorded.
        finding_scan = injection.scan_fields(injection.finding_fields(finding))
        if finding_scan["blocked"]:
            return await self._reject(
                finding, change_class, created_by,
                reason="prompt-injection detected in finding fields: " + finding_scan["summary"],
                injection_checks={"finding": finding_scan},
                summary=f"[blocked] {change_class}: injected finding",
            )

        # LAYER 2 inputs: resolve DB-authoritative parameters for the diff.
        try:
            spec, repo = await self._build_spec(finding, change_class)
        except SpecError as exc:
            return await self._reject(
                finding, change_class, created_by,
                reason=f"could not build fix spec: {exc}",
                injection_checks={"finding": finding_scan},
                summary=f"[rejected] {change_class}: {exc}",
            )

        # LAYER 2: generate the diff deterministically.
        try:
            gd = self._generate(change_class, spec)
        except gen.GeneratorError as exc:
            return await self._reject(
                finding, change_class, created_by,
                reason=f"deterministic generator refused: {exc}",
                injection_checks={"finding": finding_scan},
                summary=f"[rejected] {change_class}: {exc}",
                repo=repo,
            )

        # LAYER 3: the deterministic diff gate (authoritative; re-parses diff).
        gate_res = gate_mod.check(
            gd.unified, gd.change_class, gd.spec,
            max_files=self.cfg.max_files,
            max_changed_lines=self.cfg.max_changed_lines,
            max_bytes=self.cfg.max_diff_bytes,
        )
        if not gate_res.ok:
            return await self._reject(
                finding, change_class, created_by,
                reason="diff gate rejected: " + "; ".join(gate_res.reasons),
                injection_checks={"finding": finding_scan},
                verifier_report={"gate": gate_res.as_dict()},
                diff=gd.unified, summary=f"[rejected] {gd.summary}", repo=repo,
            )

        # LAYER 1: build PR title/body (sanitized template + optional LLM prose).
        explanation = await self._explain(gd, finding)
        title, body = self._pr_text(gd, finding, explanation, gate_res, repo)

        # LAYER 5: scan the generated PR title/body. Refuse to carry injected
        # instructions into a PR.
        pr_scan = injection.scan_fields({"pr_title": title, "pr_body": body})
        injection_checks = {"finding": finding_scan, "pr": pr_scan}
        if pr_scan["blocked"]:
            return await self._reject(
                finding, change_class, created_by,
                reason="generated PR body would carry injected instructions: " + pr_scan["summary"],
                injection_checks=injection_checks,
                verifier_report={"gate": gate_res.as_dict()},
                diff=gd.unified, summary=f"[rejected] {gd.summary}", repo=repo,
            )

        # LAYER 4: adversarial verify (rule-based + optional stricter LLM).
        vres = await verify_mod.verify(
            finding, gd.change_class, gd.unified, gd.spec, llm=self.llm
        )
        verifier_report = {
            "gate": gate_res.as_dict(),
            "verify": vres.as_dict(),
            "explanation": explanation,
        }
        if not vres.ok:
            return await self._reject(
                finding, change_class, created_by,
                reason="verifier rejected: " + "; ".join(vres.reasons),
                injection_checks=injection_checks,
                verifier_report=verifier_report,
                diff=gd.unified, summary=f"[rejected] {gd.summary}", repo=repo,
            )

        # All layers passed -> VERIFIED. Optionally open a PROPOSED PR (LAYER 6).
        head_branch = f"auto-remediation/{gd.change_class}/{str(finding['id'])[:8]}"
        status = "verified"
        pr_url = pr_number = None
        pr_info = {"opened": False}
        can, why = gh.can_open(self.cfg)
        if can:
            pr = gh.open_pr(
                self.cfg, head_branch=head_branch, title=title, body=body,
                diff_text=gd.unified,
            )
            pr_info = {
                "opened": pr.opened, "reason": pr.reason,
                "pr_url": pr.pr_url, "pr_number": pr.pr_number,
            }
            if pr.opened:
                status, pr_url, pr_number = "pr_open", pr.pr_url, pr.pr_number
        else:
            pr_info = {"opened": False, "reason": why}
        verifier_report["pr"] = pr_info

        rec = {
            "finding_id": str(finding["id"]),
            "repo": repo,
            "kind": gd.change_class,
            "summary": gd.summary,
            "base_branch": self.cfg.base_branch,
            "head_branch": head_branch,
            "diff": gd.unified,
            "status": status,
            "verifier_report": verifier_report,
            "injection_checks": injection_checks,
            "pr_url": pr_url,
            "pr_number": pr_number,
            "created_by": created_by,
            "verified_at": now(),
        }
        saved = await self.db.insert_remediation(rec)
        return {"ok": True, "remediation": saved, "title": title, "body": body}

    # ------------------------------------------------------------------
    # helpers
    # ------------------------------------------------------------------
    async def _build_spec(
        self, finding: dict[str, Any], change_class: str
    ) -> tuple[dict[str, Any], str | None]:
        meta = finding.get("metadata") if isinstance(finding.get("metadata"), dict) else {}
        ev = finding.get("evidence") if isinstance(finding.get("evidence"), dict) else {}
        config_path = (meta or {}).get("config_path") or (ev or {}).get("config_path")
        base_content = (meta or {}).get("base_content") or (ev or {}).get("base_content")
        repo = (meta or {}).get("repo") or self.cfg.github_repo

        if change_class == "dependency_bump":
            resolved = await self.db.resolve_dependency_spec(finding)
            if not resolved:
                raise SpecError("no SCA component/vuln resolves from the DB for this finding")
            if not resolved.get("fixed_version"):
                raise SpecError("OSV has no fixed_version for this vulnerability")
            spec = {
                "ecosystem": resolved.get("ecosystem"),
                "package": resolved.get("package"),
                "current_version": resolved.get("current_version"),
                "fixed_version": resolved.get("fixed_version"),  # DB-authoritative
                "osv_id": resolved.get("osv_id"),
                "cve_id": resolved.get("cve_id"),
                "lockfile_path": (meta or {}).get("lockfile_path") or (ev or {}).get("lockfile_path"),
                "base_content": base_content,
            }
            return spec, resolved.get("repo") or repo

        if change_class == "security_header":
            header = (meta or {}).get("header") or (ev or {}).get("header")
            if not header:
                header = _sniff_header(finding)
            return {"header": header, "config_path": config_path, "base_content": base_content}, repo

        if change_class in ("config_fix", "tls_fix"):
            return {"config_path": config_path, "base_content": base_content}, repo

        if change_class == "dotfile_block":
            return {"config_path": config_path, "base_content": base_content}, repo

        raise SpecError(f"unknown change class {change_class!r}")  # pragma: no cover

    def _generate(self, change_class: str, spec: dict[str, Any]) -> gen.GeneratedDiff:
        if change_class == "dependency_bump":
            return gen.generate_dependency_bump(spec)
        if change_class == "security_header":
            return gen.generate_security_header(spec)
        if change_class in ("config_fix", "tls_fix"):
            return gen.generate_tls_fix(spec)
        if change_class == "dotfile_block":
            return gen.generate_dotfile_block(spec)
        raise gen.GeneratorError(f"no generator for {change_class!r}")  # pragma: no cover

    async def _explain(self, gd: gen.GeneratedDiff, finding: dict[str, Any]) -> str:
        llm_text = None
        try:
            llm_text = await self.llm.explain(gd.change_class, gd.summary, finding)
        except Exception:  # pragma: no cover - defensive
            llm_text = None
        if llm_text:
            # The LLM output is itself untrusted; sanitize before use.
            return injection.sanitize(llm_text)
        return _template_explanation(gd)

    def _pr_text(
        self, gd: gen.GeneratedDiff, finding: dict[str, Any], explanation: str,
        gate_res: gate_mod.GateResult, repo: str | None,
    ) -> tuple[str, str]:
        # The title is built from DB-sourced facts only (never raw finding text).
        title = f"[automated-fix] {gd.summary}"
        body = (
            f"## Proposed automated fix ({gd.change_class})\n\n"
            f"{explanation}\n\n"
            f"- Change class: `{gd.change_class}`\n"
            f"- File: `{gd.path}`\n"
            f"- Deterministic change: {gd.summary}\n"
            + (f"- OSV fixed_version (DB-verified): `{gd.spec.get('fixed_version')}`\n"
               if gd.change_class == "dependency_bump" else "")
            + "\n### Verification\n"
            f"- Diff gate: PASS ({gate_res.report.get('added_lines', 0)} added, "
            f"{gate_res.report.get('removed_lines', 0)} removed, "
            f"{len(gate_res.report.get('files', []))} file(s))\n"
            "- Prompt-injection scan: no injected instructions in finding or PR body\n"
            "- Adversarial verifier: addresses the finding; no out-of-scope changes\n\n"
            "> This PR was PROPOSED by palantir-asm auto-remediation. It is "
            "constrained to an allowlisted change class and double-checked for "
            "prompt injection. **It is NOT auto-merged — a human must review and "
            "approve.**\n"
        )
        return title, body

    async def _reject(
        self, finding: dict[str, Any], change_class: str, created_by: str, *,
        reason: str, summary: str,
        injection_checks: dict[str, Any] | None = None,
        verifier_report: dict[str, Any] | None = None,
        diff: str | None = None, repo: str | None = None,
    ) -> dict[str, Any]:
        report = dict(verifier_report or {})
        report["rejection_reason"] = reason
        rec = {
            "finding_id": str(finding["id"]),
            "repo": repo,
            "kind": change_class,
            "summary": summary[:500],
            "base_branch": self.cfg.base_branch,
            "head_branch": None,
            "diff": diff,
            "status": "rejected",
            "verifier_report": report,
            "injection_checks": injection_checks or {},
            "pr_url": None,
            "pr_number": None,
            "created_by": created_by,
            "verified_at": None,
        }
        saved = await self.db.insert_remediation(rec)
        log.info("remediation rejected (finding=%s): %s", finding.get("id"), reason)
        return {"ok": False, "status": "rejected", "reason": reason, "remediation": saved}


class SpecError(ValueError):
    pass


def _template_explanation(gd: gen.GeneratedDiff) -> str:
    if gd.change_class == "dependency_bump":
        s = gd.spec
        return (
            f"Upgrades {s.get('package')} from {s.get('current_version')} to the "
            f"OSV-confirmed fixed version {s.get('fixed_version')} "
            f"({s.get('osv_id') or s.get('cve_id') or 'advisory'}), removing the "
            "known-vulnerable version from the lockfile."
        )
    if gd.change_class == "security_header":
        return f"Adds the missing {gd.spec.get('header')} response header to the web server configuration."
    if gd.change_class in ("config_fix", "tls_fix"):
        return "Pins ssl_protocols to TLS 1.2/1.3, disabling the deprecated TLS 1.0/1.1 protocols."
    if gd.change_class == "dotfile_block":
        return "Adds a web-server rule that blocks public access to /.git and other dotfiles."
    return gd.summary  # pragma: no cover


def _sniff_header(finding: dict[str, Any]) -> str:
    blob = f"{finding.get('rule_id','')} {finding.get('title','')} {finding.get('description','')}".lower()
    for key in gen.SECURITY_HEADER_TEMPLATES:
        if key in blob or key.replace("-", " ") in blob:
            return key
    # common short names
    if "hsts" in blob:
        return "strict-transport-security"
    if "csp" in blob:
        return "content-security-policy"
    if "clickjack" in blob or "frame" in blob:
        return "x-frame-options"
    return ""
