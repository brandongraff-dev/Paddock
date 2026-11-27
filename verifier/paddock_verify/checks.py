# SPDX-License-Identifier: Apache-2.0
"""The verification pipeline: steps 0 to 10 of spec/07-verification-procedure.md.

``verify`` is pure: all input arrives through the ``Bundle`` (a source of files), the resolver set, the optional
state and the arguments; it returns a ``Report`` and never writes anything (the caller applies
``report.state_update``). Any unexpected exception becomes ``internal.error`` (exit 2), never a pass.

Abort rules: a reject in step 0 or 1 ends the run; an unsupported predicateType continues with steps 2 and 3 only;
a reject in steps 2 to 4 leaves steps 5 to 10 ``not_evaluated`` (policy is never judged on unauthentic data);
steps 5 to 10 collect every reason in step order.
"""
from __future__ import annotations

import hashlib
import os
import re
from typing import Any, Callable, Dict, List, Optional, Tuple

from . import anchor as anchor_mod
from . import b64, canon, codes, dsse, ed25519, jsonstrict, keys as keys_mod, limits, model, policy as policy_mod, revocation, schema
from . import timefmt, wording
from .dns import resolver as dns_resolver
from .dns import txtparse
from .fetch import FetchError
from .jsonstrict import JsonError
from .report import Reason, Report, key_line, result_lines, REVOCATION_NOT_CHECKED
from .state import State, StateError

_RANK = {"declared": 0, "configured": 1, "observed": 2, "tested": 3}
_CHECK_IDS = ("input", "schema", "signature", "trust", "revocation", "time", "chain", "disclosure", "results", "policy", "anchor")
MODE_FULL, MODE_SELFCHECK = "full", "issuer_selfcheck"


class _Abort(Exception):
    pass


def _cap(assertion: str) -> int:
    return _RANK["configured"] if assertion == "host-config" else _RANK["observed"]


def _epoch(now: Any) -> int:
    if now is None:
        return timefmt.now_epoch()
    if isinstance(now, str):
        return timefmt.parse(now)
    if isinstance(now, bool) or not isinstance(now, int):
        raise TypeError("now is an epoch or a timestamp")
    return now


class _Run(object):
    def __init__(self, bundle: model.Bundle, policy: policy_mod.Policy, now: int, resolvers: Optional[dns_resolver.ResolverSet],
                 state: Any, roots: keys_mod.TrustRoots, registry: model.Registry, expected_domain: Optional[str],
                 dns_record: Optional[str], max_anchor_age_s: int, history_depth: int, proofs: Optional[anchor_mod.ProofLoader],
                 anchor_bytes: Optional[bytes], mode: str, dns_timeout: float) -> None:
        self.bundle, self.policy, self.now, self.resolvers, self.state, self.roots, self.registry = bundle, policy, now, resolvers, state, roots, registry
        self.expected_domain, self.dns_record, self.max_anchor_age_s, self.history_depth = expected_domain, dns_record, max_anchor_age_s, history_depth
        self.proofs, self.anchor_bytes, self.mode, self.dns_timeout = proofs, anchor_bytes, mode, dns_timeout
        self.reasons = []  # type: List[Reason]
        self.seen = set()  # type: set
        self.env = None  # type: Optional[dsse.Envelope]
        self.env_bytes = b""
        self.stmt = None  # type: Optional[Dict[str, Any]]
        self.pred = None  # type: Optional[Dict[str, Any]]
        self.subject = None  # type: Optional[schema.Subject]
        self.unsupported = False
        self.keys = None  # type: Optional[keys_mod.KeysDoc]
        self.entry = None  # type: Optional[keys_mod.Entry]
        self.sig_ok = False
        self.chain = None  # type: Optional[keys_mod.ChainResult]
        self.vendor_certified = None  # type: Optional[bool]
        self.dns_bound = None  # type: Optional[bool]
        self.dnssec = "unknown"
        self.revocation_list = None  # type: Optional[revocation.RevocationList]
        self.revocation_checked = False
        self.revocation_status = ""
        self.issued_at = now
        self.valid_until = now
        self.prev = None  # type: Optional[Dict[str, Any]]
        self.state_update = None  # type: Optional[Dict[str, Any]]
        self.derived = []  # type: List[Dict[str, Any]]
        self.limits_id = None  # type: Optional[str]
        self.status = {}  # type: Dict[int, str]
        self.missing_std = []  # type: List[str]
        self.human_lines = []  # type: List[str]

    # ------------------------------------------------------------------------------------------ plumbing
    def add(self, code: str, params: Optional[Dict[str, Any]] = None, cls: Optional[str] = None) -> None:
        c = codes.get(code)
        if c is None:
            raise KeyError(code)
        if code in self.seen:
            existing = [r for r in self.reasons if r.code == code][0]
            if existing.cls == "W" and (cls or c.cls) != "W":          # an R/U of the same code replaces a warning
                self.reasons = [r for r in self.reasons if r.code != code]
            else:
                return
        self.seen.add(code)
        self.reasons.append(Reason(code, cls or c.cls, c.step, params or {}))

    def failing(self, steps: Tuple[int, ...]) -> bool:
        return any(r.cls in ("R", "U") and r.step in steps for r in self.reasons)

    def rejected(self, steps: Tuple[int, ...]) -> bool:
        return any(r.cls == "R" and r.step in steps for r in self.reasons)

    # ----------------------------------------------------------------------------------------------- run
    def run(self) -> Report:
        evaluated = 0
        try:
            if self._parse():
                self._signature()
                self._trust()
                if not self.unsupported:
                    self._revocation()
                    if not self.rejected((2, 3, 4)) and self.sig_ok:
                        evaluated = 5
                        self._after_authentic()
            self.human_lines = self._human(self._authentic() and evaluated > 0)
        except _Abort:
            pass
        except Exception:                                  # never a pass
            if os.environ.get("PADDOCK_VERIFY_DEBUG"):
                import traceback
                traceback.print_exc()
            self.reasons = [r for r in self.reasons]
            self.seen.add("internal.error")
            self.reasons.append(Reason("internal.error", "U", None, {}))
        try:
            return self._report(evaluated)
        except Exception:
            rep = Report()
            rep.reasons = [Reason("internal.error", "U", None, {})]
            rep.checks = [{"step": i, "id": _CHECK_IDS[i], "status": "not_evaluated", "codes": []} for i in range(11)]
            return rep.finish()

    def _authentic(self) -> bool:
        return self.stmt is not None and not self.unsupported and self.sig_ok and not self.failing((0, 1, 2, 3, 4))

    def _after_authentic(self) -> None:
        self._time()
        self._chain()
        self._disclosure()
        self._results()
        if self.mode != MODE_SELFCHECK:
            self._policy()
        self._anchor()
        self._state_update()

    # ----------------------------------------------------------------------------------------- steps 0, 1
    def _parse(self) -> bool:
        try:
            self.env_bytes = self.bundle.envelope()
        except FetchError as e:
            self.add(e.code)
            return False
        try:
            self.env = dsse.parse_envelope(self.env_bytes, expected_type=dsse.PAYLOAD_TYPE_STATEMENT)
            stmt = canon.roundtrip(self.env.payload, max_depth=limits.MAX_STATEMENT_DEPTH)
        except JsonError as e:
            self.add(e.code)
            return False
        issues, unsupported = schema.validate_statement(stmt)
        for issue in issues:
            self.add(issue.code, {"path": issue.path})
        if issues:
            return False
        self.stmt = stmt
        self.subject = schema.parse_subject(stmt["subject"][0]["name"])
        self.pred = stmt["predicate"]
        if unsupported:
            self.unsupported = True
            self.add("predicate.unsupported_version")
            # best effort for the certificate windows: only well-formed timestamps are used
            for attr, key in (("issued_at", "issued_at"), ("valid_until", "valid_until")):
                v = self.pred.get(key) if isinstance(self.pred, dict) else None
                try:
                    setattr(self, attr, timefmt.parse(v))
                except (JsonError, TypeError):
                    pass
            return True
        self.issued_at = timefmt.parse(self.pred["issued_at"])
        self.valid_until = timefmt.parse(self.pred["valid_until"])
        self.limits_id = self.pred["limits"]["id"]
        return True

    # ------------------------------------------------------------------------------------------- step 2
    def _signature(self) -> None:
        env = self.env
        assert env is not None
        try:
            data = self.bundle.read("keys.json", limits.MAX_AUX_FILE_BYTES)
        except FetchError as e:
            self.add(e.code)
            return
        if data is None:
            self.add("keys.missing")
            return
        try:
            self.keys = keys_mod.parse_keys(data)
        except keys_mod.KeysError as e:
            self.add(e.code)
            return
        self.entry = self.keys.entries.get(env.keyid)
        if self.entry is None:
            self.add("key.unknown")
            return
        if not self.unsupported and self.pred["kid"] != env.keyid:
            self.add("key.kid_mismatch")
        if self.entry.alg != keys_mod.ALG:
            self.add("sig.alg_unsupported")
            return
        code = ed25519.verify_code(self.entry.public_key, dsse.pae(dsse.PAYLOAD_TYPE_STATEMENT, env.payload), env.sig)
        if code:
            self.add(code)
        else:
            self.sig_ok = True

    # ------------------------------------------------------------------------------------------- step 3
    def _trust(self) -> None:
        entry, keys = self.entry, self.keys
        if entry is None or keys is None:
            return
        estate = None if self.unsupported else self.pred["estate"]
        pol = self.policy
        if not self.roots:
            self.add("config.no_trust_roots")
            if ed25519.kid_of(entry.public_key) != entry.kid:
                self.add("key.fingerprint_mismatch")
        else:
            estate_clash = self.subject is not None and self.subject.kind == "estate" and estate is not None and self.subject.value != estate
            optional_missing = pol.vendor_cert == "optional" and entry.cert is None
            chain = keys_mod.check_chain(entry.cert, keys, self.roots, self.issued_at, self.valid_until, "attest", estate, entry,
                                         force_subject_mismatch=estate_clash)
            self.chain = chain
            for code in chain.codes:
                if code == "key.cert_missing" and optional_missing:
                    self.add(code, cls="W")
                else:
                    self.add(code)
            self.vendor_certified = (not chain.codes) and chain.chain_ok
        for code in keys_mod.integrity(keys, self.roots, entry.kid):
            self.add(code, cls="W" if (code == "key.cert_missing" and pol.vendor_cert == "optional") else None)
        if self.mode != MODE_SELFCHECK:
            self._dns()

    def _dns(self) -> None:
        subject, pol = self.subject, self.policy
        if subject is None or self.entry is None:
            return
        if subject.kind != "dns":
            self.add("dns.not_applicable", cls="R" if (pol.profile == "policy" and pol.dns_binding == "required") else "W")
            return
        expected = self.expected_domain if self.expected_domain is not None else self._bundle_domain()
        if expected is not None and expected != subject.value:
            self.add("dns.domain_mismatch")
            self.dns_bound = False
            return
        operator = self.dns_record is not None
        optional = pol.dns_binding == "optional"
        if operator:
            records = [[self.dns_record]]
            ad = "unknown"
        elif self.resolvers is None:
            self.add("dns.skipped_offline", cls="W" if optional else None)
            return
        else:
            q = self.resolvers.lookup("_paddock-attest." + subject.value, self.dns_timeout)
            if q.error:
                self.add(q.error)
                return
            records = [[r] for r in q.records]
            ad = q.ad
        self.dnssec = ad
        rr = txtparse.parse_rrset(records)
        if rr.too_many:
            self.add("dns.too_many_records")
            return
        if any(r.status == txtparse.STATUS_MALFORMED for r in rr.records):
            self.add("dns.record_ignored")
        kid = self.env.keyid  # type: ignore[union-attr]
        mine = [r for r in rr.records if r.status == txtparse.STATUS_OK and r.kid == kid]
        if not mine:
            self.add("dns.no_binding")
            self.dns_bound = False
            return
        if len(set(r.fp for r in mine)) > 1:
            self.add("dns.record_conflict")
            self.dns_bound = False
            return
        cert_pub = self.chain.cert.public_key if (self.chain is not None and self.chain.cert is not None) else self.entry.public_key
        if mine[0].fp != ed25519.fingerprint(cert_pub):
            self.add("dns.mismatch")
            self.dns_bound = False
            return
        self.dns_bound = True
        if operator:
            self.add("dns.skipped_offline", cls="W" if optional else None)
            self.dns_bound = None
        if pol.dnssec == "required" and ad != "ad_asserted":
            self.add("dns.dnssec_unproven")

    def _bundle_domain(self) -> Optional[str]:
        """The domain a bundle says it is for (``bundle.json``, an unsigned convenience): it can only add a reject."""
        try:
            raw = self.bundle.read("bundle.json", limits.MAX_AUX_FILE_BYTES)
            doc = jsonstrict.parse(raw, max_depth=limits.MAX_PCJ_DEPTH) if raw is not None else None
        except (FetchError, JsonError):
            return None
        d = doc.get("domain") if isinstance(doc, dict) else None
        return d if isinstance(d, str) and d else None

    # ------------------------------------------------------------------------------------------- step 4
    def _revocation(self) -> None:
        keys, entry = self.keys, self.entry
        if keys is None or entry is None or not self.roots:
            return
        pred, pol = self.pred, self.policy
        chain = self.chain
        if chain is not None and chain.cert is not None and chain.cert.issuer_kid in self.roots.revoked_issuers:
            self.add("issuer.revoked")
            return
        try:
            data = self.bundle.read("revoked.json", limits.MAX_AUX_FILE_BYTES)
        except FetchError as e:
            self.add(e.code)
            return
        floor = self.state.revocation_seq(pred["estate"]) if isinstance(self.state, State) else 0
        ev = revocation.evaluate(data, keys, self.roots, pred["estate"], self.now, pol.revocation_max_age_s, floor)
        best = pol.revocation == "best_effort"
        w = "W" if best else None
        if ev.status == "missing":
            self.add("revocation.missing", cls=w)
        elif ev.status == "unverifiable":
            self.add("revocation.unverifiable", {"why": ev.why}, cls=w)
        elif ev.status == "stale":
            self.add("revocation.stale", cls=w)
        self.revocation_checked = ev.status in ("ok", "stale")
        self.revocation_status = ev.status
        if ev.list is not None:
            self.revocation_list = ev.list
            issuer_kids = [chain.cert.issuer_kid] if (chain is not None and chain.cert is not None) else []
            if chain is not None and chain.issuer is not None:
                issuer_kids.append(chain.issuer.kid)
            for f in revocation.apply(ev.list, entry.kid, self.issued_at, self.subject.name, pred["seq"], issuer_kids):  # type: ignore[union-attr]
                self.add(f.code, f.params, cls=f.cls)

    # ------------------------------------------------------------------------------------------- step 5
    def _time(self) -> None:
        pred, pol = self.pred, self.policy
        issued, valid = self.issued_at, self.valid_until
        snap = timefmt.parse(pred["snapshot"]["at"])
        if self.now >= valid:
            self.add("time.expired")
        if self.now < issued - limits.SKEW_SECONDS:
            self.add("time.not_yet_valid")
        anchor_at = timefmt.parse(pred["audit_anchor"]["at"]) if "audit_anchor" in pred else None
        if valid <= issued or snap > issued or issued > snap + limits.SNAPSHOT_MAX_GAP_SECONDS or (anchor_at is not None and anchor_at > issued):
            self.add("time.window_invalid")
        if valid > issued and valid - issued > limits.MAX_TTL_SECONDS:
            self.add("time.ttl_excessive")
        if self.now - issued > pol.max_age_s or self.now - snap > pol.max_age_s:
            self.add("time.too_old", {"max_age_s": pol.max_age_s})

    # ------------------------------------------------------------------------------------------- step 6
    def _read_statement(self, path: str) -> Optional[Tuple[bytes, Dict[str, Any], dsse.Envelope]]:
        """A history file as (raw bytes, statement, envelope) or ``None`` when it is absent or unusable."""
        try:
            raw = self.bundle.read(path, limits.MAX_ENVELOPE_BYTES)
        except FetchError:
            return None
        if raw is None:
            return None
        try:
            env = dsse.parse_envelope(raw, expected_type=dsse.PAYLOAD_TYPE_STATEMENT)
            st = canon.loads(env.payload, max_depth=limits.MAX_STATEMENT_DEPTH)
        except JsonError:
            return None
        if not isinstance(st, dict) or not isinstance(st.get("predicate"), dict):
            return None
        return raw, st, env

    def _chain(self) -> None:
        pred, pol = self.pred, self.policy
        seq = pred["seq"]
        name = self.subject.name  # type: ignore[union-attr]
        digest = "sha256:" + hashlib.sha256(self.env.payload).hexdigest()  # type: ignore[union-attr]
        if pol.history != "off" and self.mode != MODE_SELFCHECK:
            self._history(seq, pred, digest)
        if isinstance(self.state, StateError):
            self.add("chain.state_unreadable")
        elif self.state is not None:
            known = self.state.subject(name)
            if known is not None:
                if seq < known["seq"]:
                    self.add("chain.seq_rollback")
                elif seq == known["seq"] and digest != known["digest"]:
                    self.add("chain.fork")
                elif seq == known["seq"] + 1 and pred.get("prev") != known["digest"]:
                    self.add("chain.prev_mismatch")
                a, claimed = known.get("anchor"), pred.get("audit_anchor")
                if a is not None and claimed is not None and seq > known["seq"]:
                    if claimed["max_id"] < a["max_id"] or timefmt.parse(claimed["at"]) < timefmt.parse(a["at"]):
                        self.add("anchor.max_id_regressed")
                    elif claimed["max_id"] == a["max_id"] and claimed["head"] != a["head"]:
                        self.add("anchor.mismatch", {"why": "same_max_id_other_head"})

    def _history(self, seq: int, pred: Dict[str, Any], digest: str) -> None:
        pol = self.policy
        is_latest = self.bundle.envelope_file is None or os.path.basename(self.bundle.envelope_file) == "latest.json"
        if is_latest:
            numbered = None
            try:
                numbered = self.bundle.read("attestation/%d.json" % seq, limits.MAX_ENVELOPE_BYTES)
            except FetchError:
                pass
            if numbered is not None and numbered != self.env_bytes:
                self.add("chain.latest_mismatch")
        if "prev" not in pred:
            return
        found = self._predecessor(seq, pred["prev"])
        if found is None:
            self.add("chain.history_missing", cls="U" if pol.history == "required" else "W")
            return
        kind, prev_stmt = found
        if kind == "mismatch":
            self.add("chain.prev_mismatch")
            return
        if kind == "gap":
            self.add("chain.seq_gap")
            return
        self.prev = prev_stmt
        pp = prev_stmt["predicate"]
        try:
            if pred["policy"]["total"] < pp["policy"]["total"] or pred["policy"]["versions"] < pp["policy"]["versions"]:
                self.add("policy.shrank")
            if "audit_anchor" in pred and "audit_anchor" in pp:
                a, b = pred["audit_anchor"], pp["audit_anchor"]
                if a["max_id"] < b["max_id"] or timefmt.parse(a["at"]) < timefmt.parse(b["at"]):
                    self.add("anchor.max_id_regressed")
            old = dict((r["invariant"], r["digest"]) for r in pp["results"])
            if any(r["invariant"] in old and old[r["invariant"]] != r["digest"] for r in pred["results"]):
                self.add("digest.changed")
        except (KeyError, TypeError):
            self.add("chain.prev_mismatch")
            return
        # deeper history: every earlier link must also hold, as far as the files are there
        cur_seq, cur = seq - 1, prev_stmt
        for _ in range(max(0, self.history_depth - 1)):
            cp = cur["predicate"]
            if cp.get("seq") != cur_seq or "prev" not in cp or cur_seq < 2:
                break
            nxt = self._predecessor(cur_seq, cp["prev"])
            if nxt is None:
                break
            if nxt[0] != "ok":
                self.add("chain.prev_mismatch" if nxt[0] == "mismatch" else "chain.seq_gap")
                break
            cur_seq, cur = cur_seq - 1, nxt[1]

    def _predecessor(self, seq: int, prev: str) -> Optional[Tuple[str, Dict[str, Any]]]:
        """Locate the statement that ``prev`` names. Returns ``(kind, statement)`` with kind ok, mismatch or gap."""
        direct = self._read_statement("attestation/%d.json" % (seq - 1))
        if direct is not None:
            raw, st, env = direct
            if "sha256:" + hashlib.sha256(env.payload).hexdigest() != prev:
                return "mismatch", st
            if st["predicate"].get("seq") != seq - 1:
                return "gap", st
            return "ok", st
        # not at its expected name: the (unsigned) index may point at the file the hash belongs to
        try:
            idx = self.bundle.read("attestation/index.json", limits.MAX_AUX_FILE_BYTES)
            entries = jsonstrict.parse(idx, max_depth=limits.MAX_PCJ_DEPTH) if idx is not None else []
        except (FetchError, JsonError):
            return None
        for e in entries if isinstance(entries, list) else []:
            if isinstance(e, dict) and e.get("statement_digest") == prev and type(e.get("seq")) is int and 1 <= e["seq"] < seq - 1:
                other = self._read_statement("attestation/%d.json" % e["seq"])
                if other is not None and "sha256:" + hashlib.sha256(other[2].payload).hexdigest() == prev:
                    return "gap", other[1]
        return None

    # ------------------------------------------------------------------------------------------- step 7
    def _disclosure(self) -> None:
        pred, pol = self.pred, self.policy
        lim = pred["limits"]
        known = limits.limits_digest(lim["id"])
        if known is None:
            self.add("limits.unknown")
        elif known != lim["digest"]:
            self.add("limits.digest_mismatch")
        strict = pol.std_registry == "strict"
        warn_cls = None if strict else "W"
        ruleset = self.registry.rulesets.get(pred["engine"]["ruleset"])
        if ruleset is None:
            self.add("engine.ruleset_unknown", cls=warn_cls)
        version = pred["engine"]["version"]
        for adv in self.registry.advisories:
            if adv.get("engine") == version:
                aid = adv.get("id")
                self.add("engine.advisory", {"id": aid if isinstance(aid, str) and re.match(r"[A-Za-z0-9._-]{1,32}\Z", aid) else "unnamed"},
                         cls="W" if (pol.engine_advisories == "warn" or adv.get("effect") == "warn") else "R")
        std_results = [r for r in pred["results"] if r["invariant"].startswith("std:")]
        if ruleset is not None:
            table = ruleset["std"]
            for r in std_results:
                e = table.get(r["invariant"])
                if e is not None and (r["digest"] != e["digest"] or e.get("status") == "withdrawn"):
                    self.add("std.digest_mismatch", cls=warn_cls)
            for r in std_results:
                if r["invariant"] not in table:
                    self.add("std.id_unknown", cls=warn_cls)
            have = set(r["invariant"] for r in std_results)
            self.missing_std = sorted(i for i in table if i not in have and table[i].get("status") != "withdrawn")
        d, p = pred["disclosure"], pred["policy"]
        bad = False
        if d["verdicts"] == "all" and d["custom"] and p["disclosed"] != p["enabled_std"] + p["enabled_custom"]:
            bad = True
        if d["verdicts"] == "all" and not d["custom"] and len(std_results) != p["enabled_std"]:
            bad = True
        if not d["custom"] and any(not r["invariant"].startswith("std:") for r in pred["results"]):
            bad = True
        if bad:
            self.add("disclosure.inconsistent")

    # ------------------------------------------------------------------------------------------- step 8
    def _results(self) -> None:
        pred = self.pred
        names = self._names()
        for r in pred["results"]:
            cov, sel = r["coverage"], r["selected"]
            verdict = r["verdict"]
            holds = verdict == "HOLDS"
            cov_ok = True
            if holds:
                tier = r["tier"]
                if tier not in ("configured", "observed"):
                    self.add("result.tier_invalid")
                else:
                    if _RANK[tier] < _RANK[r["min_tier"]]:
                        self.add("result.tier_below_min")
                    if _RANK[tier] > _cap(r["assertion"]):
                        self.add("result.tier_above_cap")
            if cov["covered"] > cov["universe"] or cov["estate_covered"] > cov["estate_universe"]:
                self.add("result.coverage_inconsistent")
                cov_ok = False
            if holds:
                if cov["universe"] < 1:
                    self.add("result.universe_empty")
                    cov_ok = False
                elif cov["covered"] <= cov["universe"] and not limits.coverage_meets(cov["covered"], cov["universe"], cov["required_bp"]):
                    self.add("result.coverage_inconsistent")
                    cov_ok = False
                if sel["to"] < 1:
                    self.add("result.selected_empty")
                if timefmt.parse(r["valid_until"]) <= self.issued_at:
                    self.add("result.valid_until_invalid")
            if "stop_at" in sel and sel["stop_at"] * 2 > cov["estate_universe"]:
                self.add("result.boundary_dominant")
            status = verdict
            if holds and self.now >= timefmt.parse(r["valid_until"]):
                status = "EXPIRED"
            row = {"invariant": r["invariant"], "verdict": verdict, "status": status, "tier": r.get("tier"),
                   "coverage": {"covered": cov["covered"], "universe": cov["universe"], "required_bp": cov["required_bp"],
                                "percent_floor": (cov["covered"] * 100 // cov["universe"]) if cov["universe"] >= 1 else 0},
                   "valid_until": r.get("valid_until"), "exceptions": r["exceptions"]}
            if verdict == "VIOLATED":
                row["violations"] = r["violations"]
            if verdict == "UNKNOWN":
                row["reason_codes"] = list(r["reason_codes"])
            row["_name"] = names.get(r["invariant"])
            row["_cov_ok"] = cov_ok
            self.derived.append(row)

    def _names(self) -> Dict[str, Optional[str]]:
        rs = self.registry.rulesets.get(self.pred["engine"]["ruleset"])
        out = {}  # type: Dict[str, Optional[str]]
        for r in self.pred["results"]:
            e = rs["std"].get(r["invariant"]) if (rs is not None and r["invariant"].startswith("std:")) else None
            out[r["invariant"]] = e["name"] if e is not None else None
        return out

    # ------------------------------------------------------------------------------------------- step 9
    def _policy(self) -> None:
        pred, pol = self.pred, self.policy
        by_id = dict((d["invariant"], d) for d in self.derived)
        consistent = lambda d: d["_cov_ok"] and d["coverage"]["universe"] >= 1 and d["coverage"]["covered"] <= d["coverage"]["universe"]  # noqa: E731
        snap = timefmt.parse(pred["snapshot"]["at"])
        raw = dict((r["invariant"], r) for r in pred["results"])
        required = set(q.invariant for q in pol.require)
        for q in pol.require:
            d = by_id.get(q.invariant)
            if d is None:
                self.add("invariant.missing")
                continue
            r = raw[q.invariant]
            if d["verdict"] == "VIOLATED":
                self.add("invariant.verdict_violated")
                continue
            if d["verdict"] == "UNKNOWN":
                self.add("invariant.verdict_unknown")
                continue
            if d["status"] == "EXPIRED":
                self.add("invariant.expired")
            if q.min_tier is not None and _RANK.get(r["tier"], -1) < _RANK[q.min_tier]:
                self.add("invariant.tier_below_required")
            bp = q.min_coverage_bp
            if bp is not None and consistent(d) and not limits.coverage_meets(r["coverage"]["covered"], r["coverage"]["universe"], bp):
                self.add("coverage.below_threshold")
            if q.digest is not None and r["digest"] != q.digest:
                self.add("invariant.digest_mismatch")
            if pol.max_exceptions is not None and r["exceptions"] > pol.max_exceptions:
                self.add("invariant.exceptions_over_limit")
            if pol.max_stop_at_share_bp is not None and "stop_at" in r["selected"] \
                    and r["selected"]["stop_at"] * 10000 > pol.max_stop_at_share_bp * r["coverage"]["estate_universe"]:
                self.add("result.boundary_dominant", cls="R")
            if q.max_age_s is not None and self.now - snap > q.max_age_s:
                self.add("invariant.age_exceeded", {"max_age_s": q.max_age_s})
        for d in self.derived:
            if d["verdict"] == "HOLDS" and consistent(d):
                r = raw[d["invariant"]]
                if not limits.coverage_meets(r["coverage"]["covered"], r["coverage"]["universe"], pol.min_coverage_bp):
                    self.add("coverage.below_threshold")
        for d in self.derived:
            if d["verdict"] == "VIOLATED" and d["invariant"] not in required:
                self.add("invariant.unrequired_violation", cls="W" if pol.violations == "warn" else "R")
        dis, p = pred["disclosure"], pred["policy"]
        if pol.disclosure == "complete" and not (dis["verdicts"] == "all" and p["disclosed"] == p["enabled_std"] + p["enabled_custom"]):
            self.add("policy.disclosure_incomplete")
        if pol.require_latest and self._newer_exists(pred["seq"]):
            self.add("chain.not_latest")

    def _newer_exists(self, seq: int) -> bool:
        best = seq
        latest = self._read_statement("attestation/latest.json")
        if latest is not None and type(latest[1]["predicate"].get("seq")) is int:
            best = max(best, latest[1]["predicate"]["seq"])
        try:
            idx = self.bundle.read("attestation/index.json", limits.MAX_AUX_FILE_BYTES)
            entries = jsonstrict.parse(idx, max_depth=limits.MAX_PCJ_DEPTH) if idx is not None else []
        except (FetchError, JsonError):
            entries = []
        for e in entries if isinstance(entries, list) else []:
            if isinstance(e, dict) and type(e.get("seq")) is int:
                best = max(best, e["seq"])
        return best > seq

    # ------------------------------------------------------------------------------------------ step 10
    def _anchor(self) -> None:
        pred, pol = self.pred, self.policy
        claimed = pred.get("audit_anchor")
        mode = pol.anchor
        if self.mode == MODE_SELFCHECK:
            mode = "optional" if self.anchor_bytes is not None else "off"
        if self.anchor_bytes is not None and mode == "off":
            mode = "optional"
        if mode == "off" and self.proofs is None:
            return
        if mode != "off":
            if claimed is None:
                if mode == "required":
                    self.add("anchor.unavailable", {"why": "no_audit_anchor_field"}, cls="R")
            else:
                data = self.anchor_bytes
                bundle_doc = None
                try:
                    bundle_doc = self.bundle.read("anchors/%d.json" % claimed["max_id"], limits.MAX_AUX_FILE_BYTES)
                except FetchError as e:
                    self.add(e.code)
                if data is None:
                    data = bundle_doc
                elif bundle_doc is not None and bundle_doc != data:
                    self.add("anchor.mismatch", {"why": "independent_copy_differs"})
                    data = None
                if data is None and "anchor.mismatch" not in self.seen:
                    self.add("anchor.unavailable", cls="W" if mode == "optional" else "U")
                elif data is not None:
                    for f in anchor_mod.check_anchor(data, claimed, pred["estate"], self.issued_at, self.keys, self.roots,
                                                     self.revocation_list, self.max_anchor_age_s):
                        self.add(f.code, f.params)
        if self.proofs is not None:
            for f in anchor_mod.check_proofs(self.proofs, pred):
                self.add(f.code, f.params)

    # --------------------------------------------------------------------------------------- state update
    def _state_update(self) -> None:
        if self.failing((0, 1, 2, 3, 4)) or self.pred is None:
            return
        pred = self.pred
        sub = {"name": self.subject.name, "seq": pred["seq"], "digest": "sha256:" + hashlib.sha256(self.env.payload).hexdigest()}  # type: ignore[union-attr]
        if "audit_anchor" in pred:
            a = pred["audit_anchor"]
            sub["anchor"] = {"max_id": a["max_id"], "at": a["at"], "head": a["head"]}
        upd = {"subject": sub}  # type: Dict[str, Any]
        if self.revocation_list is not None:
            upd["revocation"] = {"estate": pred["estate"], "seq": self.revocation_list.seq}
        self.state_update = upd

    # ------------------------------------------------------------------------------------------ report
    def _report(self, evaluated: int) -> Report:
        rep = Report()
        pol = self.policy
        try:
            rep.now = timefmt.format(self.now)
        except timefmt.TimeError:
            rep.now = ""
        rep.profile = pol.profile
        rep.policy_name = pol.name
        rep.policy_sha256 = pol.sha256
        rep.custom_roots = self.roots.custom
        rep.target = self.bundle.label
        ordered = sorted(self.reasons, key=lambda r: (r.step if r.step is not None else 99))
        rep.reasons = [r for r in ordered if r.cls in ("R", "U")]
        rep.warnings = [r for r in ordered if r.cls == "W"]
        authentic = self._authentic()
        rep.checks = self._checks(evaluated)
        if self.subject is not None:
            rep.subject = self.subject.name
        if self.entry is not None and self.sig_ok:
            rep.key = {"kid": self.entry.kid, "custody": self.entry.custody, "vendor_certified": self.vendor_certified,
                       "dns_bound": self.dns_bound, "dnssec": self.dnssec}
        if self.pred is not None and not self.unsupported:
            p = self.pred["policy"]
            tiers = [d["tier"] for d in self.derived if d["verdict"] == "HOLDS" and d["tier"] in _RANK]
            rep.statement = {"seq": self.pred["seq"], "issued_at": self.pred["issued_at"], "valid_until": self.pred["valid_until"],
                             "snapshot_at": self.pred["snapshot"]["at"],
                             "policy": {"total": p["total"], "enabled_std": p["enabled_std"], "enabled_custom": p["enabled_custom"],
                                        "disclosed": p["disclosed"], "disabled": p["total"] - p["enabled_std"] - p["enabled_custom"]},
                             "min_tier": min(tiers, key=lambda t: _RANK[t]) if tiers else None,
                             "missing_std": list(self.missing_std)}
            rep.limits_id = self.limits_id if limits.limits_text(self.limits_id or "") is not None else None
        if authentic and evaluated:
            rep.results = [dict((k, v) for k, v in d.items() if not k.startswith("_")) for d in self.derived]
        rep.human_lines = list(self.human_lines)
        if self.state_update is not None and "internal.error" not in self.seen \
                and not any(r.cls in ("R", "U") and r.step in (0, 1, 2, 3, 4) for r in self.reasons):
            rep.state_update = self.state_update
        if self.revocation_checked is False and self.policy.revocation == "best_effort" and self.entry is not None and self.roots:
            rep.human_lines.append(REVOCATION_NOT_CHECKED)
        return rep.finish()

    def _checks(self, evaluated: int) -> List[Dict[str, Any]]:
        out = []
        halted = self.rejected((0, 1))                # steps after a reject in 0 or 1 never ran
        by_step = {}  # type: Dict[int, List[Reason]]
        for r in self.reasons:
            by_step.setdefault(r.step if r.step is not None else -1, []).append(r)
        for step in range(11):
            rs = by_step.get(step, [])
            if any(r.cls == "R" for r in rs):
                status = "fail"
            elif any(r.cls == "U" for r in rs):
                status = "unverifiable"
            elif step <= 1:
                status = "pass" if self.stmt is not None or (step == 0 and self.env is not None) else "not_evaluated"
            elif step in (2, 3, 4):
                status = self._early_status(step, halted)
            else:
                status = "pass" if evaluated else "not_evaluated"
                if evaluated and ((step == 9 and self.mode == MODE_SELFCHECK) or (step == 10 and not self._anchor_ran())):
                    status = "skip"
            out.append({"step": step, "id": _CHECK_IDS[step], "status": status, "codes": [r.code for r in rs]})
        return out

    def _early_status(self, step: int, halted: bool) -> str:
        if halted or self.stmt is None:
            return "not_evaluated"
        if step == 2:
            return "pass" if self.sig_ok else "not_evaluated"
        if step == 3:
            return "pass" if self.entry is not None else "not_evaluated"
        if step == 4:
            if self.unsupported or self.entry is None or not self.roots:
                return "skip" if (self.entry is not None and not self.roots) else "not_evaluated"
            return "pass"
        return "not_evaluated"

    def _anchor_ran(self) -> bool:
        return self.policy.anchor != "off" or self.anchor_bytes is not None or self.proofs is not None

    def _human(self, show_results: bool) -> List[str]:
        lines = []  # type: List[str]
        pred = self.pred
        if self.entry is not None and self.sig_ok:
            lines.append(key_line(self.entry.custody, self.vendor_certified, self.dns_bound, self.dnssec))
        if pred is None or self.unsupported or self.subject is None:
            return lines
        if not show_results:
            return lines
        lines.append(wording.render("W-VALID", subject=self.subject.name, issued_at=pred["issued_at"], valid_until=pred["valid_until"]))
        n_hold = 0
        for d in self.derived:
            lines.extend(result_lines(d["invariant"], d["_name"], d))
            if d["status"] == "HOLDS":
                n_hold += 1
        p = pred["policy"]
        enabled = p["enabled_std"] + p["enabled_custom"]
        lines.append(wording.render("W-POLICY", disclosed=p["disclosed"], enabled=enabled, disabled=p["total"] - enabled, k=max(0, enabled - n_hold)))
        n_std_missing = p["enabled_std"] - sum(1 for r in pred["results"] if r["invariant"].startswith("std:"))
        if n_std_missing > 0:
            lines.append(wording.render("W-STD-MISSING", n=n_std_missing))
        if pred["valid_until"] and self.now >= self.valid_until:
            lines.append(wording.render("W-EXPIRED-ATT", valid_until=pred["valid_until"]))
        return lines


# ---------------------------------------------------------------------------------------------- public API
def verify(bundle: model.Bundle, policy: Optional[policy_mod.Policy] = None, *, now: Any = None,
           resolver: Optional[dns_resolver.ResolverSet] = None, state: Any = None,
           roots: Optional[keys_mod.TrustRoots] = None, registry: Optional[model.Registry] = None,
           expected_domain: Optional[str] = None, dns_record: Optional[str] = None,
           max_anchor_age_s: int = limits.DEFAULT_MAX_ANCHOR_AGE_SECONDS, history_depth: int = 1,
           proofs: Optional[anchor_mod.ProofLoader] = None, anchor_bytes: Optional[bytes] = None,
           mode: str = MODE_FULL, dns_timeout: float = 5.0) -> Report:
    """Run steps 0 to 10 over ``bundle`` and return the report. Pure: nothing is written."""
    try:
        t = _epoch(now)
        if roots is None:
            roots = keys_mod.load_default_roots()
        if registry is None:
            registry = model.load_default_registry()
        run = _Run(bundle, policy or policy_mod.baseline(), t, resolver, state, roots, registry, expected_domain, dns_record,
                   max_anchor_age_s, max(1, history_depth), proofs, anchor_bytes, mode, dns_timeout)
    except Exception:
        rep = Report()
        rep.reasons = [Reason("internal.error", "U", None, {})]
        rep.checks = [{"step": i, "id": _CHECK_IDS[i], "status": "not_evaluated", "codes": []} for i in range(11)]
        return rep.finish()
    return run.run()


def verify_envelope(envelope: bytes, keys: Any, roots: Any, now: Any, mode: str = MODE_SELFCHECK, *, revoked: Optional[bytes] = None,
                    anchor: Optional[bytes] = None, registry: Optional[model.Registry] = None,
                    policy: Optional[policy_mod.Policy] = None, state: Optional[State] = None,
                    history: Optional[Dict[int, bytes]] = None) -> Report:
    """Verify one envelope given the estate's ``keys.json`` and the roots, entirely in memory (the issuer's self-check).

    ``keys`` is the bytes of ``keys.json``; ``roots`` a ``TrustRoots``, the bytes of a roots file, or a list of root
    dicts. In ``issuer_selfcheck`` mode DNS is skipped and no consumer policy (step 9) is applied.
    """
    import json
    from .fetch import MemorySource

    def raw(x: Any) -> bytes:
        if not isinstance(x, (bytes, bytearray, memoryview)):          # bytes(12) would be twelve zero bytes: be strict
            raise TypeError("bytes expected")
        return bytes(x)

    try:
        files = {"keys.json": json.dumps(keys).encode("ascii") if isinstance(keys, dict) else raw(keys)}
        if revoked is not None:
            files["revoked.json"] = raw(revoked)
        for seq, data in (history or {}).items():
            files["attestation/%d.json" % seq] = raw(data)
        files["attestation/latest.json"] = raw(envelope)
        b = model.Bundle(MemorySource(files), "attestation/latest.json", label="envelope")
        if isinstance(roots, keys_mod.TrustRoots):
            r = roots
        elif isinstance(roots, (bytes, bytearray)):
            r = keys_mod.parse_roots(bytes(roots), custom=True)
        elif isinstance(roots, (list, dict)):
            r = keys_mod.parse_roots(json.dumps(roots).encode("ascii"), custom=True)
        else:
            raise TypeError("roots")
        anchor_raw = None if anchor is None else raw(anchor)
    except Exception:                                                  # bad arguments are an unverifiable result, never an exception
        rep = Report()
        rep.reasons = [Reason("internal.error", "U", None, {})]
        rep.checks = [{"step": i, "id": _CHECK_IDS[i], "status": "not_evaluated", "codes": []} for i in range(11)]
        return rep.finish()
    return verify(b, policy, now=now, roots=r, registry=registry, state=state, mode=mode, anchor_bytes=anchor_raw)
