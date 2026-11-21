# Tier 4 contract — reachability + SAST + adaptive ML

Schema: `schema/010_tier4.sql`. Five streams, scoped by tree. All detection/analysis/prioritization — never exploitation. The ML learns from the platform's OWN data (analyst triage, change history) to rank + flag anomalies; it does not generate exploits or attacks.

| Stream | Owns | Writes |
|---|---|---|
| A. codeanalysis (NEW `codeanalysis/`) | whole dir + 1 compose block | reachability on `sbom_component_vulns`, `code_findings`, findings(`sast`) |
| B. fusion rule (correlation) | `correlation/app/engine/fusion.py` + 1 rule | `finding_chains` (fusion chains) |
| C. mlrisk (NEW `mlrisk/`) | whole dir + 1 compose block | `ml_models`, `ml_risk_scores`, `anomalies` |
| D. orchestrator | new routers | read + ack |
| E. dashboard | new pages | — |

## A. codeanalysis service (NEW `codeanalysis/`, HTTP :8097)
Mirror `sca/` shape. Two capabilities, both static:
- **Reachability**: build a call graph of first-party source (per language, best-effort: Python via AST/`ast`+import graph, JS/TS via a lightweight module+symbol scan, Go via package refs). For each `sbom_component_vulns` row whose OSV advisory names an affected symbol/module, determine reachable | potential | unreachable from app entrypoints; write `reachability`, `reachable_symbol`, `call_path`. If the advisory has no symbol or source is absent → `unknown` (don't guess). Drops noise massively; prioritize `reachable`.
- **SAST**: run **Semgrep** (`semgrep --config auto --json`) over the project source when the binary is present; else a bundled fallback taint-pattern scanner (source→sink regex/AST for: SQLi via string-built queries, command injection, path traversal, insecure deserialization (pickle/yaml.load), SSRF, hardcoded secrets/crypto). Normalize each hit → a `code_findings` row AND a unified `findings` row (`rule_source='sast'`, severity mapped, evidence=dataflow). CWE where known.
- Jobs: `POST /analyze {project_name, source_ref?, files:{path:content}}` (files are untrusted DATA — never import/execute them; read-only AST). `GET /healthz /readyz /stats`. `POST /reachability {project}` regrades existing SBOM vulns. Tool-unavailable (no semgrep / no source) → emit an info note, never crash.
- compose block mirroring `sca`.

## B. Reachability × attack-path fusion (correlation)
`correlation/app/engine/fusion.py` + a built-in fusion rule. Produce a `finding_chains` row (chain_rule_id `reachable_on_path`) when: a dependency vuln is `reachability='reachable'` on a host that also sits on an internet-facing attack_path to a crown jewel. severity = escalate (medium→high, high→critical) because it's both reachable in code AND reachable on the surface. Narrative explains the compound (same safety guard as existing narratives — no exploitation text). Run on the sweep + on `finding_opened`. Add `POST /fuse` trigger + counts in `/stats`.

## C. mlrisk service (NEW `mlrisk/`, HTTP :8098)
Mirror `intel/` shape. Deps: `scikit-learn`, `numpy`, asyncpg, aiohttp. Two models, periodic retrain (`MLRISK_INTERVAL_MIN`, default 30) + triggers.
- **Adaptive risk ranker** (`app/risk_model.py`): features per open finding — severity ordinal, cvss, epss, kev flag, reachability (reachable=2/potential=1/else 0), on_attack_path (bool + max path exploitability), internet_exposed (bool), blast_score, asset env (prod weight), finding age, rule_source one-hot, sca/sast flags. Labels from the `ml_training_labels` view (1=acted-on/resolved, 0=dismissed, NULL=unlabeled). Train a gradient-boosting (or logistic) classifier on labeled rows; predict `ml_risk` 0–100 for ALL open findings; write `ml_risk_scores` with the feature vector + a rationale (top contributing features via feature_importance * value). **Cold start**: if < `MIN_LABELS` (default 12) labeled samples, use a transparent heuristic prior (weighted sum of the same features) and mark the model `cold_start=true` — still produces scores, clearly flagged. Version every training run in `ml_models`; mark newest active.
- **Anomaly detector** (`app/anomaly.py`): IsolationForest (or robust z-score fallback) over per-asset / per-host feature vectors (open-port count, tech count, finding severities, blast, change-velocity) + change-stream velocity. Flag outliers into `anomalies` with a human-readable `reason` ("host exposes 6 ports; peer median is 2" / "change velocity 5x baseline") and a score. These surface non-obvious issues rules don't encode.
- Feedback loop: retrain picks up new labels automatically; `/stats` shows model version, n_samples, cold_start, top features. Endpoints: `/healthz /readyz /stats`, `POST /retrain`, `POST /score`, `POST /detect-anomalies`. Degrade: if sklearn import fails, heuristic prior + z-score fallback keep it working (guarded optional import).
- compose block mirroring `intel`.

## D. Orchestrator endpoints (additive)
- Reachability/SAST: `GET /v1/sbom/components` gains `reachability` rollup per component; `GET /v1/code-findings?project=&severity=&limit=&offset=` (paged, with dataflow); `GET /v1/code-findings/{id}`.
- ML: `GET /v1/ml/risk?limit=&offset=` (paged, findings joined with ml_risk DESC incl rationale + finding/asset summary); `GET /v1/ml/model` (active models + metrics + feature importance + cold_start); `GET /v1/anomalies?acknowledged=&limit=&offset=` (paged); `POST /v1/anomalies/{id}/ack`; `POST /v1/ml/retrain` (proxy to mlrisk, degrade if down).
- Config `codeanalysis_url` (http://codeanalysis:8097), `mlrisk_url` (http://mlrisk:8098). Proxies degrade cleanly ({available:false}) when down. Keep 123+ tests green.

## E. Dashboard
- **Dependencies** page: add a `reachability` column/badge (reachable=red "reachable", potential=amber, unreachable=grey "not reached", unknown=faint) + a "reachable only" filter toggle. Add a **Code (SAST)** section or page: code_findings with file:line, rule, severity, and an expandable source→sink dataflow trace.
- **Risk Model** (`/risk-model`, NEW): header tiles (model version, samples trained, cold-start?, anomalies open). A "Top adaptive-risk findings" table ranked by `ml_risk` with a rationale popover (the top contributing signals — e.g. "reachable +22, on KEV path +18, prod +10"). A "Model insights" panel showing feature importances (horizontal bars) + a note on how it learns from triage. An "Anomalies" feed: subject, score, reason, ack button. Make the "learns from your triage, adapts over time, explainable" story explicit and honest (show cold-start state when applicable).
- api modules `src/api/code.ts`, `src/api/ml.ts`; types `ReachabilityGrade`,`CodeFinding`,`DataflowStep`,`MlRiskScore`,`MlModel`,`Anomaly`. Nav icons (code/branch, brain/spark). Routes in App.tsx. Match the dark/dense system; no slop. The ML page must read as a transparent analyst aid (scores + reasons), not a black box.

## Safety recap
Static analysis + learned prioritization + anomaly detection over the owner's own data. No exploit generation, no attack automation, no evasion. Reachability/SAST read source as inert data (never execute it). The ML explains its scores (feature contributions) and flags cold-start; it ranks and surfaces, humans decide.
