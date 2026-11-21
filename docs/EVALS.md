# Detection-quality evals

Two engines (SAST and typosquat) once shipped as silent no-ops because their
rule data was missing and nothing measured them. The eval harness makes that
impossible to repeat: every detector is run against labelled cases in CI, and
the build fails when precision or recall drops, or when a detector stops
firing at all.

```
python hardening/evals/run.py              # all engines, table + exit code
python hardening/evals/run.py --engine sca -v
python hardening/evals/run.py --json out.json
pytest hardening/evals/test_harness.py     # harness self-tests
```

CI runs both in the `evals` job (`.github/workflows/ci.yml`).

## How it works

| Piece | Where | What |
|---|---|---|
| Ranges | `hardening/evals/ranges/*.yaml` | labelled cases per engine: positives **and** look-alikes |
| Adapters | `hardening/evals/engines.py` | feed a case to the engine's **real** detection code, report which detectors fired |
| Harness | `hardening/evals/harness.py` | scores TP/FP/FN/TN per detector, applies floors, prints the table |
| Floors | `hardening/evals/thresholds.yaml` | minimum precision/recall per `engine/detector` (default 1.0) |

Engines covered today:

| Engine | Code under test | Detectors |
|---|---|---|
| `sast` | `codeanalysis/app/sast/taint_fallback.py` + `data/taint_rules.json` (Python AST, JS/TS + Go regex) | sql_injection, command_injection, code_injection, path_traversal, ssrf, insecure_deserialization, weak_crypto, hardcoded_secret, insecure_transport |
| `sca` | `sca/app/risk/*` + `data/popular_packages.json` | typosquat, dependency_confusion, unpinned, malicious_version, yanked, abandoned |
| `ot_fingerprint` | `otdiscovery/app/fingerprint/*` (OUI, mDNS/SSDP, DHCP, OT protocols) | role:ot, role:iot |
| `ot_behaviour` | `otdiscovery/app/behavior.py` | device_lateral_scan, ot_internet_egress, cleartext_management, iot_crosses_segment, behavior_drift |
| `scope` | `orchestrator/app/scope.py` | reject, canonical, in_scope |
| `correlation` | `correlation/app/engine/{policy,chain}.py` + shipped chain YAMLs | one detector per chain rule |

The correlation adapter replaces only the SQL candidate fetch with an
in-memory asset graph; rule loading, predicate matching and rule satisfaction
are the engine's own code. Policy rules (raw SQL) are not covered yet.

A detector **fails** when any of these hold:

* recall or precision is below its floor;
* it has no positive case (untested) or no negative case (no look-alike);
* it has positives but never fires (the silent no-op);
* the engine fails to import or crashes on any case.

Floors below 1.0 are recorded debt: each names the `KNOWN GAP` / `KNOWN FP`
cases that cost it. Raise the floor in the same PR that fixes the engine;
lower one only with a reviewer's sign-off and a reason in the YAML comment.

## Adding a case from a customer report

When a customer reports a false positive or a missed issue, the fix starts
with a case, so it can never regress.

1. **Reduce it.** Strip the report to the smallest input that reproduces it,
   with no customer data: rename hosts to `acme.io`/`example.com`, use RFC 5737
   / RFC 1918 addresses, rewrite code to a few lines, replace secrets with
   synthetic ones that keep the same shape.
2. **Pick the range** for the engine (`ranges/sast_python.yaml`,
   `ranges/sca.yaml`, ...) and append a case:

   ```yaml
   # false positive reported by a customer (ticket ref, no customer names)
   - id: js-token-url-not-secret        # unique within the engine, kebab-case
     lang: javascript
     expect: []                         # false positive -> must stay silent
     note: URL assigned to a token-named variable is not a credential
     code: |
       const tokenUrl = "https://auth.acme.io/oauth2/v1/token";

   # missed issue (false negative)
   - id: js-sqli-concat-before-call
     lang: javascript
     expect: [sql_injection]            # the detector(s) that must fire
     code: |
       const sql = "SELECT * FROM users WHERE id = " + req.query.id;
       db.query(sql);
   ```

   Add the **look-alike twin** too: for a missed issue, a safe variant that
   must stay quiet; for a false positive, a real variant that must still fire.
   That pair is what keeps a fix from over-correcting.
3. **Run it:** `python hardening/evals/run.py --engine sast -v`. The new case
   shows up under `missed (FN)` or `false alarm (FP)` and the gate fails.
4. **Fix the engine** (rule data, detector code) until the gate passes at the
   existing floors. If the fix is not in this PR, mark the case
   `note: KNOWN GAP ...` / `KNOWN FP ...` and lower that detector's floor in
   `thresholds.yaml` to the measured value with a comment naming the case.
   The debt is then visible in every CI run.
5. **Close the loop with the customer's instance:** the false positive they
   marked in the dashboard (`POST /v1/findings/{id}/false-positive`, optionally
   `"suppress": true`) keeps their noise down until the engine fix ships;
   the case keeps everyone else from seeing it again.

Case fields per engine:

| Engine | Fields |
|---|---|
| `sast` | `lang` (python, javascript, typescript, go), `code`, optional `file` |
| `sca` | `component` {ecosystem, name, version, metadata.spec}, optional `osv`, `yanked`, `last_release`, `public_names` (clock fixed at 2026-11-01) |
| `ot_fingerprint` | `observations` (arp/packet/flow/mdns/ssdp/dhcp dicts), `subject` {ip or mac} |
| `ot_behaviour` | `observations`, `flows`, `subject`, optional `params`, `baseline: true` + `learn_flows` |
| `scope` | `target`, optional `canonical`, optional `entries` [{kind, value}] |
| `correlation` | `assets` [{id, kind, value, host, metadata}], `findings` [{asset, rule_id, rule_source, ...}] |

## Adding an engine

Write an adapter class in `engines.py` (`name`, `service`, `detectors`,
`detect(imp, case, ctx)`, optional `prepare(imp)`), register it in
`ADAPTERS`, add a range with positives and look-alikes for every detector,
and install the service in the CI `evals` job. `test_harness.py` fails until
every declared detector has both kinds of case.

## Measured today

```
engine         detector                              pos  neg   TP   FP   FN  prec   rec
correlation    (5 chain rules)                         5   80    5    0    0  1.00  1.00
ot_behaviour   behavior_drift                          1   21    1    0    0  1.00  1.00
ot_behaviour   cleartext_management                    3   19    3    0    0  1.00  1.00
ot_behaviour   device_lateral_scan                     2   20    2    0    0  1.00  1.00
ot_behaviour   iot_crosses_segment                     2   20    2    0    0  1.00  1.00
ot_behaviour   ot_internet_egress                      1   21    1    0    0  1.00  1.00
ot_fingerprint role:iot                                6   18    6    1    0  0.86  1.00
ot_fingerprint role:ot                                 8   16    8    1    0  0.89  1.00
sast           code_injection                          1   56    1    0    0  1.00  1.00
sast           command_injection                       5   52    4    0    1  1.00  0.80
sast           hardcoded_secret                        4   53    4    2    0  0.67  1.00
sast           insecure_deserialization                2   55    2    0    0  1.00  1.00
sast           insecure_transport                      2   55    2    0    0  1.00  1.00
sast           path_traversal                          3   54    3    0    0  1.00  1.00
sast           sql_injection                           6   51    5    0    1  1.00  0.83
sast           ssrf                                    4   53    4    0    0  1.00  1.00
sast           weak_crypto                             3   54    3    0    0  1.00  1.00
sca            abandoned                               1   39    1    0    0  1.00  1.00
sca            dependency_confusion                    4   36    4    1    0  0.80  1.00
sca            malicious_version                       1   39    1    0    0  1.00  1.00
sca            typosquat                              10   30   10    2    0  0.83  1.00
sca            unpinned                                4   36    4    1    0  0.80  1.00
sca            yanked                                  1   39    1    0    0  1.00  1.00
scope          canonical                              30   17   30    0    0  1.00  1.00
scope          in_scope                                6   41    6    0    0  1.00  1.00
scope          reject                                 17   30   17    0    0  1.00  1.00
207 cases across 6 engines
```

The open debt, in priority order (each is a `KNOWN` case in the ranges):
`@types/*` flagged as dependency confusion; `preact`/`boto` flagged as
typosquats; `tokenUrl = "https://..."` flagged as a secret; prerelease
versions containing `x` read as ranges; TCP/20000 alone marks a host OT;
macOS AirPlay receivers read as IoT; SAST misses inter-procedural taint and
SQL built before the call.
