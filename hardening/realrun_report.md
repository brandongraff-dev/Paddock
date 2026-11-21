# Real-run + false-positive report

- Generated: 2026-11-20 22:24:38Z
- Target: `scanme.nmap.org` (authorized)
- Harness: `hardening/realrun.py` — active worker SAFE modules, detection-only

> Authorized-scope-only. This run touched only an explicitly authorized target (scanme.nmap.org / loopback). No exploitation, no evasion, no credential testing was performed.

## Module execution

| module | status | detail |
|---|---|---|
| http_probe | ok | HTTP 200 at http://scanme.nmap.org/; 1 tech fingerprints |
| header_check | ok | 5 security-header findings (via http_probe) |
| exposed_file | ok | 0 finding(s) across 12 probed paths |
| tls_inspect+grade | degraded | tlsx binary not installed -> emitted tool-unavailable (info) finding, no live handshake |
| nuclei | skipped | nuclei binary not installed |

Outbound requests made (audited in-process): 16

## Findings triage (6 total, 3 actionable)

| severity | source | rule_id | verdict | title |
|---|---|---|---|---|
| medium | header_check | missing-content-security-policy | true_positive | Content-Security-Policy missing |
| medium | header_check | missing-frame-protection | true_positive | No X-Frame-Options and no CSP frame-ancestors directive |
| low | header_check | missing-x-content-type-options | true_positive | X-Content-Type-Options missing |
| info | header_check | missing-referrer-policy | true_positive_info | Referrer-Policy missing |
| info | header_check | missing-permissions-policy | true_positive_info | Permissions-Policy missing |
| info | policy | tool-unavailable-tlsx | benign_info | tlsx not installed on this worker |

## Crude false-positive rate (vs hand-labeled truth set)

- Truth set: `hardening/truth_scanme.json` (as of 2026-11-20)
- Actionable findings (severity >= low): **3**
- Flagged false positives: **0**
- **False-positive rate: 0.0%** (0/3)
- Expected-signal recall: 3/3 (100%) — present: ['missing-content-security-policy', 'missing-frame-protection', 'missing-x-content-type-options']; missing: []

> The FP rate is a crude, approximate measure over a small hand-labeled set for a single host whose live config can drift. It is meant to catch gross regressions (e.g. the exposed-file module firing on a SPA), not to be a precise accuracy metric.

## Reproduce / run the full pipeline

```bash
# On a real deployment with the stack up and the ProjectDiscovery binaries
# installed in the active worker image, run the full pipeline like this:

# 1. Bring the stack up (dev profile shown; use -f docker-compose.yml for prod):
make up

# 2. Seed the safe authorized scope (localhost + scanme.nmap.org):
make seed-scope

# 3. Confirm scanme is in scope:
make scope-list

# 4. Kick a full authorized recon scan against scanme and read results:
make scan KIND=full_recon TARGET=scanme.nmap.org
make scans-list
curl -fsS "$ORCH_URL/v1/findings?limit=100" | python3 -m json.tool

# 5. Re-run THIS harness for the crude false-positive measurement:
python3 hardening/realrun.py scanme.nmap.org

```
