# SPDX-License-Identifier: Apache-2.0
"""Stable reason codes (spec/A-reason-codes.md) and the public UNKNOWN reason-code enum.

The table below MUST equal spec/A-reason-codes.md (test_codes.py compares them). Codes are never renumbered
or reused; new codes are minor-version additions.

Classes: R reject (exit 1), U unverifiable (exit 2), W warning, X usage (exit 64). ``alt`` is the class a
code takes when the acceptance policy marks the check optional or ``warn``; ``note`` says when.
"""
from __future__ import annotations

from collections import namedtuple
from typing import Dict, Iterable, List, Optional

EXIT_ACCEPTED = 0
EXIT_REJECTED = 1
EXIT_UNVERIFIABLE = 2
EXIT_USAGE = 64

Code = namedtuple("Code", "code step_label step cls alt message note")


class _Code(Code):
    __slots__ = ()

    @property
    def spec_ref(self) -> str:
        return spec_ref(self.code)


# (step, code, class, alt, message, note) in the order of spec/A-reason-codes.md
_ROWS = (
    ('0', 'input.unreadable', 'U', None, 'Could not read the input.', ''),
    ('0', 'input.not_found', 'U', None, 'No attestation bundle at this location.', ''),
    ('0', 'input.fetch_failed', 'U', None, 'Could not download the bundle (network or server error).', ''),
    ('0', 'input.insecure_transport', 'U', None, 'Refused a non-HTTPS or unsafe address.', ''),
    ('0', 'input.too_large', 'R', None, 'A file exceeds the size limit.', ''),
    ('0', 'input.not_ascii', 'R', None, 'A file is not valid ASCII where ASCII is required.', ''),
    ('0', 'input.not_json', 'R', None, 'Not valid JSON under the strict profile.', ''),
    ('0', 'input.duplicate_key', 'R', None, 'A JSON object repeats a key.', ''),
    ('0', 'input.depth_exceeded', 'R', None, 'JSON nesting is too deep.', ''),
    ('0', 'input.number_invalid', 'R', None, 'A number is not a plain in-range non-negative integer.', ''),
    ('1', 'schema.envelope_invalid', 'R', None, 'Not a valid DSSE envelope.', ''),
    ('1', 'schema.payload_type', 'R', None, 'Unexpected payload type.', ''),
    ('1', 'schema.base64_invalid', 'R', None, 'A value is not canonical standard base64.', ''),
    ('1', 'schema.payload_not_canonical', 'R', None, 'Payload bytes are not in canonical form.', ''),
    ('1', 'schema.statement_invalid', 'R', None, 'Not a valid in-toto statement.', ''),
    ('1', 'schema.subject_invalid', 'R', None, 'Subject is missing, malformed or its digest is wrong.', ''),
    ('1', 'schema.field_unknown', 'R', None, 'A field that this version does not define is present.', ''),
    ('1', 'schema.field_invalid', 'R', None, 'A field has the wrong type or format.', 'params: JSON path'),
    ('1', 'schema.time_format', 'R', None, 'A timestamp is not YYYY-MM-DDTHH:MM:SSZ.', ''),
    ('1', 'schema.digest_format', 'R', None, 'A digest or id is malformed.', ''),
    ('1', 'schema.enum_unknown', 'R', None, 'A closed value is not recognised.', ''),
    ('1', 'schema.limit_exceeded', 'R', None, 'A list or size exceeds the allowed maximum.', ''),
    ('1', 'schema.result_duplicate', 'R', None, 'An invariant appears twice.', ''),
    ('1', 'schema.result_unsorted', 'R', None, 'Results are not sorted by invariant id.', ''),
    ('1', 'schema.result_inconsistent', 'R', None, "A result's fields contradict its verdict.", ''),
    ('1', 'schema.seq_prev_invalid', 'R', None, '`seq` and `prev` are inconsistent.', ''),
    ('1', 'schema.counts_inconsistent', 'R', None, 'Disclosed, enabled and total counts do not add up.', ''),
    ('1', 'predicate.unsupported_version', 'U', None, 'This verifier does not support that predicate version.', ''),
    ('2', 'sig.count_invalid', 'R', None, 'Version 1 requires exactly one signature.', ''),
    ('2', 'sig.malformed', 'R', None, 'Signature is not 64 canonical bytes.', ''),
    ('2', 'sig.alg_unsupported', 'U', None, 'Signature algorithm not supported.', ''),
    ('2', 'keys.missing', 'U', None, '`keys.json` not available.', ''),
    ('2', 'keys.invalid', 'R', None, '`keys.json` fails validation.', ''),
    ('2', 'key.unknown', 'R', None, 'Signing key is not in `keys.json`.', ''),
    ('2', 'key.kid_mismatch', 'R', None, 'The signed key id differs from the envelope key id.', ''),
    ('2', 'sig.weak_key', 'R', None, 'The public key is a small-order or non-canonical point.', ''),
    ('2', 'sig.noncanonical_s', 'R', None, 'The signature scalar is not reduced.', ''),
    ('2', 'sig.invalid', 'R', None, 'The signature does not match the statement.', ''),
    ('3', 'config.no_trust_roots', 'U', None, 'No trust roots are configured.', ''),
    ('3', 'key.fingerprint_mismatch', 'R', None, 'Key id does not match the public key.', ''),
    ('3', 'key.cert_missing', 'R', 'W', 'The key has no vendor certificate.', 'W when policy `vendor_cert: optional`'),
    ('3', 'key.cert_invalid', 'R', None, 'Certificate is malformed or its signature fails.', ''),
    ('3', 'key.cert_subject_mismatch', 'R', None, 'Certificate does not match the listed key, usage or estate.', ''),
    ('3', 'key.root_unknown', 'R', None, 'Certificate does not chain to a trusted root.', ''),
    ('3', 'key.outside_validity', 'R', None, 'The key was not valid when the statement was issued or for its whole lifetime.', ''),
    ('3', 'issuer.outside_validity', 'R', None, 'An issuing certificate was not valid at issue time.', ''),
    ('3', 'dns.domain_mismatch', 'R', None, 'Statement subject differs from the domain checked.', ''),
    ('3', 'dns.no_binding', 'R', None, 'The domain publishes no binding for this key.', ''),
    ('3', 'dns.mismatch', 'R', None, "The domain's published key fingerprint differs.", ''),
    ('3', 'dns.record_conflict', 'R', None, 'The domain publishes two fingerprints for one key id.', ''),
    ('3', 'dns.too_many_records', 'R', None, 'The domain publishes too many binding records.', ''),
    ('3', 'dns.record_ignored', 'W', None, 'A malformed DNS record was ignored.', ''),
    ('3', 'dns.not_applicable', 'W', 'R', 'The subject has no domain to bind.', 'R when the policy requires DNS'),
    ('3', 'dns.lookup_failed', 'U', None, 'DNS lookup failed.', ''),
    ('3', 'dns.insufficient_resolvers', 'U', None, 'Too few resolvers answered.', ''),
    ('3', 'dns.resolvers_disagree', 'U', None, 'Resolvers returned different answers.', ''),
    ('3', 'dns.skipped_offline', 'U', 'W', 'DNS binding not checked (offline).', 'W when the policy marks it optional'),
    ('3', 'dns.dnssec_unproven', 'U', None, 'DNSSEC validation required but not shown.', ''),
    ('4', 'key.revoked', 'R', None, 'The signing key was revoked.', ''),
    ('4', 'key.revoked_superseded', 'W', None, 'Key later retired; the statement predates that.', ''),
    ('4', 'issuer.revoked', 'R', None, 'An issuing key was revoked.', ''),
    ('4', 'chain.superseded', 'R', None, 'A newer statement or a supersession notice exists for this subject.', ''),
    ('4', 'revocation.missing', 'U', None, 'No revocation list available.', ''),
    ('4', 'revocation.unverifiable', 'U', None, 'Revocation list failed verification.', ''),
    ('4', 'revocation.stale', 'U', None, 'Revocation list is too old to rely on.', ''),
    ('5', 'time.expired', 'R', None, 'The attestation has expired.', ''),
    ('5', 'time.not_yet_valid', 'R', None, 'Issued in the future beyond the allowed skew.', ''),
    ('5', 'time.window_invalid', 'R', None, 'The validity window is inconsistent (`valid_until` not after `issued_at`, snapshot or anchor out of order).', ''),
    ('5', 'time.ttl_excessive', 'R', None, 'Validity period exceeds the 7-day maximum.', ''),
    ('5', 'time.too_old', 'R', None, 'Older than your maximum age.', ''),
    ('6', 'chain.seq_rollback', 'R', None, 'Sequence number is lower than one seen before.', ''),
    ('6', 'chain.fork', 'R', None, 'Two different statements share a sequence number.', ''),
    ('6', 'chain.prev_mismatch', 'R', None, 'Does not link to the previous statement.', ''),
    ('6', 'chain.seq_gap', 'R', None, 'Sequence skips a number (a withheld update).', ''),
    ('6', 'chain.latest_mismatch', 'R', None, '`latest.json` differs from the numbered statement.', ''),
    ('6', 'chain.history_missing', 'U', 'W', 'Previous statement unavailable.', 'W if optional'),
    ('6', 'chain.state_unreadable', 'U', None, 'Local state file unreadable.', ''),
    ('6', 'policy.shrank', 'R', None, 'The declared policy shrank since the previous statement.', ''),
    ('6', 'anchor.max_id_regressed', 'R', None, 'The anchored audit position went backwards.', ''),
    ('6', 'digest.changed', 'W', None, "An invariant's definition changed since the previous statement.", ''),
    ('7', 'limits.unknown', 'R', None, 'The limits statement id is not known to this verifier.', ''),
    ('7', 'limits.digest_mismatch', 'R', None, 'The limits statement text differs from the pinned one.', ''),
    ('7', 'engine.ruleset_unknown', 'U', None, "This verifier does not know the engine's ruleset.", ''),
    ('7', 'engine.advisory', 'R', 'W', 'The engine version has a known defect advisory.', 'W when policy `warn`'),
    ('7', 'std.digest_mismatch', 'R', None, "A standard invariant's definition differs from the registry.", ''),
    ('7', 'std.id_unknown', 'R', None, 'A `std:` id is not in the registry for this ruleset.', ''),
    ('7', 'disclosure.inconsistent', 'R', None, 'The disclosure counts contradict the disclosure mode.', ''),
    ('8', 'result.tier_invalid', 'R', None, 'The evidence tier is not allowed here.', ''),
    ('8', 'result.tier_below_min', 'R', None, "Evidence tier is below the invariant's own minimum.", ''),
    ('8', 'result.tier_above_cap', 'R', None, 'Evidence tier exceeds what this kind of check can show.', ''),
    ('8', 'result.coverage_inconsistent', 'R', None, 'Coverage numbers contradict the claimed verdict.', ''),
    ('8', 'result.universe_empty', 'R', None, 'Nothing is in scope; the result is vacuous.', ''),
    ('8', 'result.selected_empty', 'R', None, 'The invariant selects nothing; the result is vacuous.', ''),
    ('8', 'result.valid_until_invalid', 'R', None, "A result's validity is not after the issue time.", ''),
    ('8', 'result.boundary_dominant', 'W', None, 'Boundary labels cover most of the estate.', ''),
    ('9', 'coverage.below_threshold', 'R', None, 'Coverage is below your threshold.', ''),
    ('9', 'invariant.missing', 'R', None, 'A required invariant is not in the attestation.', ''),
    ('9', 'invariant.verdict_violated', 'R', None, 'A required invariant is violated.', ''),
    ('9', 'invariant.verdict_unknown', 'R', None, 'A required invariant cannot be determined.', ''),
    ('9', 'invariant.expired', 'R', None, "A required invariant's evidence has expired.", ''),
    ('9', 'invariant.tier_below_required', 'R', None, 'Evidence tier is below what you require.', ''),
    ('9', 'invariant.digest_mismatch', 'R', None, 'Definition differs from the one your policy pins.', ''),
    ('9', 'invariant.exceptions_over_limit', 'R', None, 'More exceptions than allowed.', ''),
    ('9', 'invariant.unrequired_violation', 'R', 'W', 'A violated invariant is disclosed.', 'W if the policy says warn'),
    ('9', 'invariant.age_exceeded', 'R', None, "A required invariant's evidence is older than your limit for it.", ''),
    ('9', 'policy.disclosure_incomplete', 'R', None, 'The issuer did not disclose every enabled invariant.', ''),
    ('9', 'chain.not_latest', 'R', None, 'A newer statement exists and the policy requires the latest.', ''),
    ('10', 'anchor.unavailable', 'U', 'W', 'Audit anchor not available.', 'W if optional; R when policy `anchor: required` and the field is absent'),
    ('10', 'anchor.not_ed25519', 'R', None, 'Anchor is not an Ed25519 v2 anchor.', ''),
    ('10', 'anchor.invalid', 'R', None, 'Anchor signature or format invalid.', ''),
    ('10', 'anchor.mismatch', 'R', None, "Anchor differs from the statement's.", ''),
    ('10', 'anchor.too_old', 'R', None, 'The anchor is older than the allowed gap before the statement.', ''),
    ('10', 'merkle.proof_missing', 'U', None, 'A requested proof was not supplied.', ''),
    ('10', 'merkle.proof_invalid', 'R', None, 'A Merkle proof does not verify.', ''),
    ('any', 'internal.error', 'U', None, 'The verifier failed internally; no decision.', ''),
    ('exit 64', 'config.policy_invalid', 'X', None, 'The acceptance policy is invalid.', 'the line number is reported; exit 64'),
    ('exit 64', 'config.usage', 'X', None, 'The command line is invalid.', 'exit 64'),
)


def spec_ref(code: str) -> str:
    """The spec file that defines the check behind ``code`` (a pointer for ``--explain``)."""
    prefix = code.split(".", 1)[0]
    return _SPEC_FILES.get(prefix, "spec/07-verification-procedure.md")


_SPEC_FILES = {
    "input": "spec/07-verification-procedure.md", "schema": "spec/02-statement-predicate.md",
    "predicate": "spec/10-versioning.md", "sig": "spec/01-conventions.md", "keys": "spec/05-keys-certs-revocation-dns.md",
    "key": "spec/05-keys-certs-revocation-dns.md", "issuer": "spec/05-keys-certs-revocation-dns.md",
    "dns": "spec/05-keys-certs-revocation-dns.md", "revocation": "spec/05-keys-certs-revocation-dns.md",
    "merkle": "spec/04-merkle.md", "anchor": "spec/B-anchor-v2.md", "config": "spec/08-acceptance-policy.md",
    "result": "spec/03-verdicts-tiers-coverage-freshness.md", "coverage": "spec/08-acceptance-policy.md",
    "invariant": "spec/08-acceptance-policy.md",
}


def _build() -> Dict[str, "_Code"]:
    table = {}  # type: Dict[str, _Code]
    for step, code, cls, alt, message, note in _ROWS:
        if code in table:
            raise ValueError("duplicate reason code " + code)
        number = int(step) if step.isdigit() else None
        table[code] = _Code(code, step, number, cls, alt, message, note)
    return table


#: code -> definition, in the order of the appendix
CODES = _build()  # type: Dict[str, _Code]


def get(code: str) -> Optional[_Code]:
    return CODES.get(code)


def explain(code: str) -> Optional[str]:
    """Text for ``--explain CODE``: message, class, step and the spec file, or ``None`` for an unknown code."""
    c = CODES.get(code)
    if c is None:
        return None
    where = "step %s" % c.step_label if c.step is not None else ("any step" if c.step_label == "any" else "exit 64")
    klass = {"R": "reject (exit 1)", "U": "unverifiable (exit 2)", "W": "warning", "X": "usage (exit 64)"}[c.cls]
    lines = ["%s: %s" % (c.code, c.message), "class: %s, %s" % (klass, where)]
    if c.alt:
        lines.append("class %s %s" % (c.alt, "when the policy allows it"))
    if c.note:
        lines.append("note: " + c.note)
    lines.append("defined in: " + c.spec_ref)
    return "\n".join(lines)


def exit_for(classes: Iterable[str]) -> int:
    """Exit code for a set of reason classes: any reject gives 1, else any unverifiable gives 2, else 0."""
    out = EXIT_ACCEPTED
    for c in classes:
        if c == "R":
            return EXIT_REJECTED
        if c == "U":
            out = EXIT_UNVERIFIABLE
        elif c != "W":
            raise ValueError("unknown reason class %r" % (c,))
    return out


# ------------------------------------------------------------------------- UNKNOWN reason codes (statement)
#: engine reason (the part before the first colon) -> public reason code (spec/02-statement-predicate.md)
REASON_PREFIX_MAP = {
    "coverage_below_required": "coverage_below_required",
    "possible_via_unknown_edges": "possible_via_unknown_edges",
    "possible_via_zone_unknown": "zone_unknown",
    "zone_unknown": "zone_unknown",
    "overlapping_selectors_too_large": "selection_too_large",
    "hosts_unknown": "host_evidence_unusable",
    "no_agent": "host_evidence_unusable",
    "agent_revoked": "host_evidence_unusable",
    "no_value": "host_evidence_unusable",
    "stale": "stale_or_missing_evidence",
    "future_timestamp": "stale_or_missing_evidence",
    "tier_below_min": "stale_or_missing_evidence",
    "no_sensor": "stale_or_missing_evidence",
    "empty_selector": "empty_selector",
    "graph_incomplete": "graph_incomplete",
    "graph_unavailable": "graph_incomplete",
    "invalid_definition": "invalid_definition",
    "evaluation_error": "evaluation_error",
}

UNKNOWN_REASON_CODES = frozenset(set(REASON_PREFIX_MAP.values()) | {"other"})


def map_engine_reason(reason: str) -> str:
    """Public reason code for one engine reason string; anything unrecognised is ``other``, never an error."""
    if not isinstance(reason, str):
        return "other"
    return REASON_PREFIX_MAP.get(reason.split(":", 1)[0], "other")


def map_reasons(reasons: Iterable[str]) -> List[str]:
    """Sorted, unique public codes for a list of engine reasons; never empty (an UNKNOWN always has a reason)."""
    out = sorted({map_engine_reason(r) for r in reasons})
    return out or ["other"]
