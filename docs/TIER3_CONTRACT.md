# Tier 3 + SCA contract

Schema: `schema/009_tier3.sql`. Six work streams scoped by service tree (no collisions). All detection/analysis/read-only — no exploitation, no evasion, no supply-chain *attack* tooling.

| Stream | Owns | Writes | Reads |
|---|---|---|---|
| A. SCA service (NEW `sca/`) | whole `sca/` + 1 compose block | `sca_projects`,`sbom_components`,`sbom_component_vulns`,`supply_chain_risks`, findings(`sca`) via orch | OSV.dev, registries (public) |
| B. Neo4j backend (NEW `graphsync/` + neo4j) | `graphsync/` + 2 compose blocks | Neo4j | assets, asset_edges, findings, attack_paths |
| C. LLM brain (NEW `brain/`) | whole `brain/` + 1 compose block | `finding_clusters`,`nl_queries` | ask_* views, findings |
| D. ATT&CK mapping (correlation) | `correlation/app/engine/attack_mapping.py` + rules | `finding_techniques` | findings |
| E. Orchestrator | new routers | read/proxy | all Tier3 tables |
| F. Dashboard | new pages | — | the endpoints |

Keep REFUSED_KINDS, scope, and all existing tests green. Additive only.

## A. SCA service (NEW `sca/`, HTTP :8094)

Mirror `intel/` shape. Detection-only supply-chain analysis.
- **Lockfile parsers** (`app/parsers/`): package-lock.json, yarn.lock, pnpm-lock.yaml, requirements.txt, poetry.lock, Pipfile.lock, go.sum/go.mod, Cargo.lock, pom.xml, Gemfile.lock. Each → list of {ecosystem,name,version,direct,depth,paths}. Build an SBOM into `sbom_components` under a `sca_projects` row.
- **Vuln matching**: OSV.dev batch API (`POST https://api.osv.dev/v1/querybatch` then `/v1/vulns/{id}`) for every component → `sbom_component_vulns` (osv_id, cve_id, severity from CVSS, fixed_version). Also emit an `sca` finding per vulnerable component on the linked repository/asset (via orch `/v1/findings/bulk`).
- **Supply-chain risk** (`app/risk/`), all DEFENSIVE detection:
  - `dependency_confusion`: an internal/private package name (scoped `@org/*`, or a name not resolvable on the public registry but referenced) that *is or could be* claimed on the public registry → flag the confusion exposure. (Detect your own exposure; never publish/claim anything.)
  - `typosquat`: Levenshtein/edit-distance ≤1–2 to a popular package in a bundled top-list → flag a possible typosquat that slipped in.
  - `abandoned`: last release age > 2y from registry metadata (best-effort; skip if offline).
  - `malicious_version`/`yanked`: match against OSV "malicious" advisories / registry yank flags.
  - `unpinned`: version range instead of a pin (npm `^`/`~`, unpinned requirements) → low-sev hygiene.
  Write `supply_chain_risks` rows.
- Jobs: `POST /scan` (body `{project_name, source_ref, files:{path:content}}` OR a path to a dir of lockfiles). `GET /healthz`,`/readyz`,`/stats`. Add a `sca` compose block.
- **Hard line**: this finds where YOU are exposed to supply-chain attacks. It does NOT search for dependency combinations to defeat controls, craft malicious packages, or assemble an attack. Refuse to add anything like that.

## B. Neo4j backend (NEW `graphsync/` + neo4j in compose, HTTP :8096)

- Add a `neo4j:5-community` service to compose (bolt 7687, http 7474, env NEO4J_AUTH). Add `graphsync` service.
- `graphsync` mirrors Postgres → Neo4j: `(:Asset {id,kind,value,blast_score})` nodes, `[:EDGE {kind}]` rels, `[:HAS_FINDING]→(:Finding {severity,kev})`. Incremental via the `neo4j_sync` cursor; full re-sync on `POST /resync`.
- Expose Cypher-powered read endpoints on :8096: `GET /paths?source=&target=&max=` (shortest exploit-weighted paths via Cypher `allShortestPaths`/`apoc` if available, else plain), `GET /blast/{asset_id}` (k-hop neighborhood + aggregate), `GET /neighborhood/{asset_id}?depth=`. The orchestrator proxies these.
- Degrade: if Neo4j is unreachable, endpoints return `{available:false}` and the service stays up (health = ok, sync = waiting). Driver = `neo4j` python package.

## C. LLM brain (NEW `brain/`, HTTP :8095)

Two capabilities; BOTH degrade without a key.
- **LLM triage** (`app/triage.py`): cluster open findings (by asset/host/rule family), and for each cluster produce a short label + impact summary + remediation. Write `finding_clusters` (engine='llm' or 'template'). With `ANTHROPIC_API_KEY`, call the Claude Messages API (model from env `ANTHROPIC_MODEL`, default a current claude-* id) via the official SDK; WITHOUT a key, fall back to deterministic template clustering (group by asset_value + severity, templated summary). Periodic pass + `POST /triage/run`.
- **NL → query** (`app/ask.py`, `POST /ask {question}`): translate the question to a SINGLE read-only SQL SELECT over ONLY the views `ask_assets`, `ask_findings`, `ask_attack_paths`. GUARD (reuse correlation's sqlglot pattern):
  1. LLM (or fallback intent-matcher for ~8 common questions) proposes SQL.
  2. Parse with sqlglot; REJECT unless it is a single SELECT referencing only the three ask_* views; reject any DDL/DML/`;`/CTE-writes/function calls that touch the FS or network.
  3. Execute in a READ-ONLY transaction with `statement_timeout` and a hard `LIMIT` (cap 500).
  4. Log every attempt to `nl_queries` (question, generated_sql, engine, ok, row_count, error).
  Return `{answer_rows, columns, generated_sql, engine, note}`. NEVER run unvalidated SQL. The views already exclude scope secrets / alert targets / credentials.
- `GET /healthz`,`/readyz`,`/stats` (key present?, clusters, queries). Add a `brain` compose block. The Anthropic SDK is an OPTIONAL import — the service must boot and self-test without it.

## D. ATT&CK mapping (correlation service)

- `correlation/app/engine/attack_mapping.py` + a bundled rules file `correlation/app/rules/attack/technique_map.yaml` (~25 mappings: e.g. exposed_file→T1190/Initial Access/CWE-22, cve_match RCE→T1190, secret_scan→T1552/Credential Access/CWE-798, takeover→T1584/Resource Development, header/tls→T1557/weakness, nuclei exposure→T1595/Reconnaissance, etc.).
- For each finding, match rules (rule_source + rule_id_regex + title_regex, priority ASC) and upsert `finding_techniques`. Run on the periodic sweep + on `finding_opened`.
- Also seed `attack_technique_map` from the YAML on startup (idempotent). Provide a coverage query helper (count findings per technique/tactic). Add an HTTP trigger `POST /map-attack` to the correlation service's existing surface.

## E. Orchestrator endpoints (new routers, additive)

- **SCA**: `GET /v1/sbom/projects`, `GET /v1/sbom/components?project=&vulnerable=&ecosystem=&limit=&offset=` (paged; include vuln count), `GET /v1/sbom/components/{id}` (with vulns), `GET /v1/supply-chain-risks?type=&severity=` (paged), `GET /v1/sbom/summary` (counts: components, vulnerable, by-risk-type).
- **ATT&CK**: `GET /v1/attack/coverage` (`{by_tactic:{...}, by_technique:[{id,technique,tactic,count}], total}`), `GET /v1/findings/{id}/techniques`.
- **Ask / clusters**: `POST /v1/ask` → proxy to brain `/ask` (env `BRAIN_URL`, default http://brain:8095); degrade to `{ok:false, note}` if brain down. `GET /v1/clusters`.
- **Neo4j**: `GET /v1/graph/paths`, `GET /v1/graph/neighborhood/{id}` → proxy to graphsync (env `GRAPHSYNC_URL`); degrade to `{available:false}` if down.
- Response shapes documented in the routers; paged endpoints reuse the `{items,total,limit,offset}` envelope.

## F. Dashboard (new pages + nav)

- **Dependencies** (`/dependencies`): project selector; SBOM table (ecosystem chip, name@version mono, direct/transitive tag, vuln badge) filterable to vulnerable-only; a vuln detail drawer (OSV id, CVE, severity, fixed version); a "Supply-chain risk" panel grouping risks by type (dependency confusion / typosquat / abandoned / unpinned …) with severity chips. Header tiles: components, vulnerable, risks.
- **ATT&CK** (`/attack`): a tactic→technique coverage view — columns = the ATT&CK tactics present, each listing techniques with a finding-count heat (darker = more). Click a technique → filtered findings. Header: techniques covered, tactics touched.
- **Ask** (`/ask`): a natural-language query box ("which internet-facing hosts run end-of-life software with a KEV CVE?"). Shows the answer as a table, the generated SQL in a collapsible mono block labelled "read-only, validated", the engine badge (llm/fallback), and a short recent-questions list. Make it clear the query is validated + read-only.
- Surface LLM triage: on the Findings page (or Overview) show cluster labels where present (small, optional — don't rebuild Findings).
- New api modules `src/api/sbom.ts`, `src/api/attack.ts`, `src/api/ask.ts`; types `SbomComponent`,`SbomVuln`,`SupplyChainRisk`,`AttackCoverage`,`AskResult`,`FindingCluster`. Nav icons (package/box, ATT&CK grid, chat/ask). Match the dark/dense system; no slop.

## Safety recap (applies to every stream)
Detection, analysis, and read-only querying only. No exploitation, no evasion, no credential handling (LLM key via env only), no supply-chain *attack* construction. The NL-query engine executes only sqlglot-validated read-only SELECTs over the three ask_* views. All outbound is either public data sources (OSV/registries) or the user-configured LLM endpoint.
