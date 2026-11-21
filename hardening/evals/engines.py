"""Engine adapters: run each engine's REAL detection code on one case.

An adapter declares ``name`` (the ``engine:`` key in a range file), the
``service`` directory whose ``app`` package it imports, the full list of
``detectors`` it is scored on, and ``detect(imp, case, ctx) -> set[str]``.
``imp`` is ``importlib.import_module`` bound to that service (see
``harness.service_modules``). Nothing here reimplements detection logic; the
adapters only translate a case into the engine's input and its output into
detector names.
"""
from __future__ import annotations

import asyncio
from datetime import datetime, timezone
from typing import Any


# --------------------------------------------------------------------------- #
# codeanalysis: SAST (bundled taint scanner; Semgrep is optional and not used
# here so the gate measures the engine every install actually ships)
# --------------------------------------------------------------------------- #

class Sast:
    name = "sast"
    service = "codeanalysis"
    detectors = [
        "sql_injection", "command_injection", "code_injection", "path_traversal", "ssrf",
        "insecure_deserialization", "weak_crypto", "hardcoded_secret", "insecure_transport",
    ]

    def prepare(self, imp):
        return imp("app.sast.taint_fallback")

    def detect(self, imp, case, tf) -> set[str]:
        lang = case.data.get("lang", "python")
        default_name = {"python": "app.py", "javascript": "app.js", "typescript": "app.ts",
                        "go": "main.go"}[lang]
        files = {case.data.get("file", default_name): case.data["code"]}
        return {h["rule_class"] for h in tf.scan_files(files)}


# --------------------------------------------------------------------------- #
# sca: supply-chain risk detectors
# --------------------------------------------------------------------------- #

class Sca:
    name = "sca"
    service = "sca"
    detectors = ["typosquat", "dependency_confusion", "unpinned", "malicious_version",
                 "yanked", "abandoned"]

    def prepare(self, imp):
        return imp("app.risk")

    def detect(self, imp, case, risk) -> set[str]:
        comp = dict(case.data["component"])
        comps = [comp]
        key = f"{comp.get('ecosystem')}|{comp.get('name')}|{comp.get('version')}"
        osv = {key: case.data.get("osv", [])}
        yanked = {key} if case.data.get("yanked") else set()
        last = case.data.get("last_release")
        last_map = {f"{comp.get('ecosystem')}|{comp.get('name')}": last} if last else {}
        now = datetime(2026, 11, 1, tzinfo=timezone.utc)  # fixed clock: ranges never rot
        hits: list[dict[str, Any]] = []
        hits += risk.typosquat.detect(comps)
        hits += risk.confusion.detect(comps, public_names=case.data.get("public_names"))
        hits += risk.pinning.detect(comps)
        hits += risk.malicious.detect(comps, osv, yanked_keys=yanked)
        hits += risk.abandoned.detect(comps, last_map, now=now)
        return {h["risk_type"] for h in hits}


# --------------------------------------------------------------------------- #
# otdiscovery: passive fingerprinting (role) + behaviour detectors
# --------------------------------------------------------------------------- #

def _subject(devices, subject: dict[str, Any]):
    ip, mac = subject.get("ip"), (subject.get("mac") or "").lower() or None
    for d in devices:
        if (ip and ip in d.ips) or (mac and d.mac == mac):
            return d
    return None


class OtFingerprint:
    """Scored per role: ``role:ot`` fires when the subject device is classified
    OT, ``role:iot`` when IoT. IT look-alikes (a workstation that *polls*
    Modbus, a laptop on a printer's VLAN) must not be pulled into OT/IoT."""

    name = "ot_fingerprint"
    service = "otdiscovery"
    detectors = ["role:ot", "role:iot"]

    def prepare(self, imp):
        return imp("app.fingerprint")

    def detect(self, imp, case, fp) -> set[str]:
        devices = fp.fingerprint_devices(case.data["observations"])
        dev = _subject(devices, case.data["subject"])
        if dev is None or dev.role not in ("ot", "iot"):
            return set()
        return {f"role:{dev.role}"}


class OtBehaviour:
    name = "ot_behaviour"
    service = "otdiscovery"
    detectors = ["device_lateral_scan", "ot_internet_egress", "cleartext_management",
                 "iot_crosses_segment", "behavior_drift"]

    def prepare(self, imp):
        return imp("app.fingerprint"), imp("app.behavior")

    def detect(self, imp, case, mods) -> set[str]:
        fp, beh = mods
        devices = fp.fingerprint_devices(case.data["observations"])
        params = beh.BehaviorParams(**(case.data.get("params") or {}))
        store = beh.BaselineStore(None)
        # optional learning phase: flows seen during the baseline window
        if case.data.get("learn_flows"):
            beh.analyze(devices, case.data["learn_flows"], params=params, baselines=store)
        res = beh.analyze(devices, case.data["flows"], params=params,
                          baselines=store if case.data.get("baseline") else None)
        subj = _subject(devices, case.data["subject"])
        if subj is None:
            return set()
        return {f["rule_id"] for f in res.findings if f["metadata"]["device_id"] == subj.key}


# --------------------------------------------------------------------------- #
# orchestrator: scope normaliser + matcher (the platform's safety invariant)
# --------------------------------------------------------------------------- #

class Scope:
    """Three detectors over ``app.scope``:

    * ``reject``    fires when the normaliser refuses the target. Positives are
                    ambiguous/hostile spellings; negatives are legitimate but
                    odd-looking targets that must still be accepted.
    * ``canonical`` fires when the target normalises to exactly ``canonical``.
    * ``in_scope``  fires when the normalised target matches the case's
                    ``entries``. Negatives are look-alikes (``example.com.evil.io``,
                    one address outside the CIDR).
    """

    name = "scope"
    service = "orchestrator"
    detectors = ["reject", "canonical", "in_scope"]

    def prepare(self, imp):
        return imp("app.scope")

    def detect(self, imp, case, scope) -> set[str]:
        import ipaddress

        target = case.data["target"]
        out = scope.normalize(target)
        fired: set[str] = set()
        if not out:
            fired.add("reject")
        elif out == case.data.get("canonical"):
            fired.add("canonical")
        entries = [dict(e, id=i) for i, e in enumerate(case.data.get("entries") or [])]
        if out and entries:
            hit, _ = scope._match_host_rules(out, entries)
            if not hit:
                try:
                    ip = ipaddress.ip_address(out)
                    hit, _ = scope._match_ip_rules(ip, entries)
                except ValueError:
                    pass
            if hit:
                fired.add("in_scope")
        return fired


# --------------------------------------------------------------------------- #
# correlation: chain rules, evaluated by the real ChainMatcher against an
# in-memory asset/finding graph (the SQL candidate fetch is replaced; the rule
# loading, predicate matching and rule satisfaction logic are the engine's).
# --------------------------------------------------------------------------- #

class Correlation:
    name = "correlation"
    service = "correlation"
    detectors: list[str] = []  # filled from the shipped rule files in prepare()

    def prepare(self, imp):
        from pathlib import Path

        policy = imp("app.engine.policy")
        chain = imp("app.engine.chain")
        rules_dir = Path(chain.__file__).resolve().parents[1] / "rules"
        loader = policy.RuleLoader(builtin_dir=str(rules_dir))
        loader.load_all()
        if loader.errors:
            raise RuntimeError(f"rule load errors: {loader.errors}")
        self.detectors = sorted(loader.chains)
        return policy, chain, loader

    def detect(self, imp, case, ctx) -> set[str]:
        policy, chain, loader = ctx
        assets = {a["id"]: {"metadata": {}, **a} for a in case.data["assets"]}
        findings = []
        for i, f in enumerate(case.data["findings"]):
            a = assets[f["asset"]]
            findings.append({
                "id": f"f{i}", "asset_id": a["id"], "rule_id": f["rule_id"],
                "rule_source": f["rule_source"], "severity": f.get("severity", "medium"),
                "cvss": f.get("cvss"), "epss": f.get("epss"), "status": f.get("status", "open"),
                "title": f.get("title", f["rule_id"]), "evidence": f.get("evidence", {}),
                "metadata": f.get("metadata", {}), "asset_kind": a["kind"],
                "asset_value": a["value"], "asset_metadata": a.get("metadata") or {},
            })

        class _Scope:
            async def candidate_asset_ids(self, anchor_asset_id, scope_name):
                anchor = assets.get(anchor_asset_id)
                if anchor is None:
                    return []
                if scope_name == "same_org":
                    return list(assets)
                return [k for k, v in assets.items() if v.get("host") == anchor.get("host")]

        class _Matcher(chain.ChainMatcher):
            async def _findings_for_predicate(self, pred, scope_ids, window_days):
                out = []
                for f in findings:
                    if f["asset_id"] not in scope_ids:
                        continue
                    if pred.asset_kind and f["asset_kind"] != pred.asset_kind:
                        continue
                    if pred.asset_metadata and not all(
                            f["asset_metadata"].get(k) == v for k, v in pred.asset_metadata.items()):
                        continue
                    if policy.finding_matches(pred, f):
                        out.append(f)
                return out

            async def _assets_for_predicate(self, pred, scope_ids):
                return [assets[i] for i in scope_ids if policy.asset_matches(pred, assets[i])]

        m = _Matcher(db=None, loader=loader)
        m._scope = _Scope()

        async def _run():
            fired: set[str] = set()
            for f in findings:
                for c in await m._evaluate_anchor(f):
                    fired.add(c.get("chain_rule_id") or c.get("rule_id"))
            return fired

        return asyncio.run(_run())


ADAPTERS = {a.name: a for a in (Sast(), Sca(), OtFingerprint(), OtBehaviour(), Scope(),
                                Correlation())}
