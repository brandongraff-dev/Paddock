# Verified findings: prove it's real, prove it's fixed

A finding is a claim until something reproduces it. Paddock re-checks findings
with **safe checks** (non-destructive, scope- and proof-gated) and records every
attempt, so each finding can carry evidence for two questions:

1. *Is it real?* -> `exploitability`
2. *Did the fix hold?* -> "verified fixed"

## States

| `exploitability` | Meaning | Effect on priority |
|---|---|---|
| `unverified` | never checked, or no safe check exists for the rule | none |
| `confirmed` | a safe check reproduced it | +15, why-factor "Verified exploitable on <date>" |
| `not_reproducible` | the check ran and the detector would no longer fire | -12, why-factor "Not reproducible on <date>" |
| `inconclusive` | target unreachable, rate-limited, WAF-blocked, or the worker could not test it | none (shown as a zero-weight factor) |

A verdict **never closes a finding by itself**. Findings also carry
`last_verified_at` and `fix_verified_at` (set when a finding marked fixed was
re-checked and could no longer be reproduced; cleared by any later status change).

## Safety guarantees

- **Methods:** HTTP `GET`/`HEAD` only (any other method raises before a socket
  is opened), TLS handshakes, TCP connect + passive banner read (nothing is ever
  written to the service). No credential guessing, no payloads, no state
  changes, no load: one or a handful of requests per check.
- **Limits:** 8 s timeout, at most 3 redirects, 16 KiB read cap per response,
  `Accept-Encoding: identity`, per-host politeness limiter, 90 s per job,
  evidence capped at 4 KiB.
- **Scope on every request:** the worker's scope guard re-checks each URL,
  including every redirect hop. Every request is written to the outbound audit log.
- **Scope AND proof-of-control:** the orchestrator queues nothing unless
  `scope.check` allows the target *and* the matched scope entry's proof is
  `verified` or `attested` (an attestation past its expiry does not count). This
  holds even when `REQUIRE_SCOPE_PROOF` is off. The worker refuses a job that
  carries no proof. A refusal is recorded on the ledger with its reason.
- **Redaction:** evidence excerpts are scrubbed (env-style `KEY=value`, secret-looking
  keys, AWS keys, bearer tokens, private keys, URL credentials, long tokens)
  and capped. Integration events carry only identifiers (verdict, check id,
  time), never excerpts.
- **No false "fixed":** errors, timeouts, 429/5xx, a 403 the site root also
  returns (a WAF), DNS timeouts, an unreachable TLS port, and TLS features this
  worker's OpenSSL cannot offer are all `inconclusive`, never `not_reproducible`.
- **Append-only ledger:** a finished `finding_verifications` row cannot be updated.

## The checks

| Check id | Finds (rule) | What it sends | Confirmed when |
|---|---|---|---|
| `exposed_file` | `exposed_file` rules (`exposed-env`, `exposed-git-head`, backups, dumps...) | GET path | 200 and the same content signature the detector uses (archives: magic bytes) |
| `admin_panel` | nuclei panel/admin/login rules | GET | login/admin UI present, or 401 with `WWW-Authenticate`; redirect to another host = not reproducible |
| `directory_listing` | dir-listing rules | GET | 200 with an auto-index page |
| `default_page` | default/welcome page rules | GET | known stock page (nginx, Apache, IIS, Tomcat...) |
| `version_disclosure` | server/version header rules | GET | `Server`/`X-Powered-By` still carries a version |
| `security_headers` | `header_check` rules | GET | the header analyzer still emits the same rule (per cookie for cookie rules) |
| `subdomain_takeover` | `subdomain-takeover` | DNS CNAME + GET `/` | CNAME still points at a provider and the provider's unclaimed fingerprint (same data file as detection) is served |
| `tls_certificate` | `expired-certificate`, `expiring-certificate`, `self-signed-certificate` | TLS handshake | leaf certificate still expired / <14 days / self-signed |
| `tls_protocol` | `missing-tls-1-3`, `legacy-tls-version` | TLS handshakes | server still tops out below 1.3 / still accepts TLS 1.0 or 1.1 |
| `tls_weak_cipher` | `weak-cipher` | TLS handshake offering only weak suites | server still negotiates one |
| `open_port` | `exposed-<service>` / `open-port` rules with a port | TCP connect, read banner | port still accepts connections |

Rules without a check get status `unsupported` on the ledger and stay `unverified`.

## Prove it's fixed

A re-check is scheduled automatically (purpose `fix`) when a finding becomes `fixed` through

- a status change (`PATCH /v1/findings/{id}`), after `VERIFY_FIX_DELAY_SEC` (60);
- a ticket closed through the ticketing sync (inbound webhook);
- a merged remediation PR: `POST /v1/remediation/{id}/merged` (delay `VERIFY_PR_DELAY_SEC`, 300).
  If the finding is not yet fixed, an exploitability re-check runs instead.

Outcomes: `not_reproducible` -> `fix_verified_at` is set ("Verified fixed",
`finding.fix_verified`); the existing *verified fix* report metric counts it
(`fix_verified_at >= closed_at`, in addition to the "asset re-observed" rule).
`confirmed` -> the finding is reopened with reason `fix did not hold`, by
`system:verification`, emitting `finding.reopened` and `finding.fix_failed`.
`inconclusive` -> it stays fixed and is retried every `VERIFY_RETRY_SEC` (600) up
to `VERIFY_MAX_ATTEMPTS` (3) per fix episode, then stays fixed-but-unverified.
A re-check of a finding that was reopened meanwhile is cancelled.

The scheduler sweep (once per tenant per tick) dispatches due rows, times out
queued jobs with no result after 30 minutes, and creates the retries.

## API

| Route | Capability | Notes |
|---|---|---|
| `POST /v1/findings/{id}/verify` | `scan` | 202 with the ledger row; 403 `{error, reason, verification_id}` when scope/proof refuses; a fixed finding gets a fix check; an in-flight check is returned with `already_in_flight` |
| `POST /v1/findings/verify/bulk` | `scan` | `{finding_ids: [...]}` up to 100; per-finding outcome |
| `GET /v1/findings/{id}/verifications` | `read` | verdict, timestamps, ledger newest first |
| `POST /v1/verifications/{id}/result` | `write` | worker callback; idempotent (409 once decided) |
| `POST /v1/remediation/{id}/merged` | `triage` | records the merge and schedules the re-check |
| `GET /v1/findings?exploitability=&fix_verified=` | `read` | filters |

Jobs are `verify_finding` scans on `queue:active`. Ledger statuses: `scheduled`,
`queued`, `done`, `refused`, `unsupported`, `error`, `cancelled`. Schema: `026_verification.sql`.

## Events

`finding.verified` (any verdict), `finding.fix_verified`, `finding.fix_failed`
join the catalogue in [Integrations](INTEGRATIONS.md); a failed fix also emits
`finding.reopened`. Ticket integrations add a comment to the linked ticket; OCSF
maps them to Update / Close.

## Dashboard

The finding drawer shows the exploitability badge, a "Verified fixed" badge, the
evidence excerpt, a **Verify now** button (analyst/admin) and the verification
history. The Findings list has an exploitability filter.
