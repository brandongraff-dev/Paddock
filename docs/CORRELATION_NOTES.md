# Correlation engine — notes

This document is the DSL spec for the `correlation` service and a
working guide for authoring new chain rules and policies.

## Mental model

An individual finding is a dot. The correlation engine draws lines
between dots:

- **Chains** — declarative rules that fire when a set of findings (and
  optionally assets) coexist on the same host / domain / CIDR / org
  inside a sliding time window. The output is a row in `finding_chains`
  plus a one-paragraph *impact narrative*.
- **Policies** — declarative rules whose body is a SELECT over the
  assets graph. When the query returns asset ids, a policy finding is
  opened against each one.

Both are hot-reloaded from the mounted `/policies` directory
(`POLICIES_DIR`). Files that fail validation are skipped and listed on
`GET /rules`.

## Layout

```
correlation/
  app/
    main.py            # FastAPI + Redis consumer + sweep + file-watcher
    engine/
      policy.py        # YAML loader + validator, pydantic models
      chain.py         # chain detector + policy evaluator
      graph.py         # async BFS/DFS over asset_edges
      blast.py         # blast-radius scorer
    narratives/writer.py  # template renderer with safety filter
    rules/             # built-in rules, overlaid by /policies
```

## Chain rule DSL

```yaml
id: unique_id_a-z0-9              # required, 3–64 chars
name: Human readable name         # required
severity: critical                # info | low | medium | high | critical
window_days: 30                   # optional, default 30
all_of:                           # 2+ entries; every one must be satisfied
  - finding:                      # predicate on a findings row
      rule_source: cve_match      # optional: exact match
      rule_id: nuclei-admin       # optional: exact match
      rule_id_match: "^cve-.*"    # optional: regex
      severity_min: high          # optional
      cvss_min: 7.0               # optional, 0.0–10.0
      epss_min: 0.5               # optional, 0.0–1.0
      known_exploited: true       # optional; matches metadata.kev
      status: open                # optional (default: open)
      asset_kind: endpoint        # optional: constrain the asset
      asset_metadata:             # optional: dict of required asset metadata keys
        env: prod
      evidence:                   # optional: dict of required evidence keys
        header: X-Forwarded-For
      metadata:                   # optional: dict of required metadata keys
        kev: true
    scope: same_host              # same_host | same_domain | same_cidr | same_org
  - asset:                        # OR: predicate on an asset row
      kind: endpoint              # required if 'asset' used
      metadata:
        public: true
    scope: same_host
impact: |                         # jinja-free single-pass template
  The host {host} runs {versions} with cvss {cvss}.
remediation:                      # optional list of strings
  - "Block /.git/ at the CDN."
references: []                    # optional
```

### Scopes

- `same_host` — same host asset (service / tech / endpoint roll up to
  the ipv4/ipv6/subdomain parent).
- `same_domain` — the same registrable domain (longest `domain` ancestor).
- `same_cidr` — the same IPv4 /24 as the anchor's IPv4 ancestor (IPv6
  falls back to `same_host`).
- `same_org` — any asset under the same `org` root.

### Template variables (impact / narrative)

Only a small, descriptive surface is exposed to the template:

| var | meaning |
|---|---|
| `{host}` | the anchor finding's asset value |
| `{severity}` | the anchor finding's severity |
| `{rule_id}` | the anchor finding's rule id |
| `{cvss}` | the anchor finding's CVSS (or empty) |
| `{versions}` | comma-separated list of versions from matched findings |
| `{paths}` | comma-separated list of evidence paths |
| `{findings_count}` | number of matched findings |

Raw evidence blobs are never exposed, so a stray `evidence.raw_response`
containing attacker output can't leak into a narrative.

## Policy rule DSL

```yaml
id: prod_requires_hsts
name: Human name
severity: medium
scope:
  asset_tag: prod
  asset_kind: endpoint
description: |
  Prose for the finding description.
query: |
  SELECT a.id
  FROM assets a
  JOIN findings f ON f.asset_id = a.id
  WHERE a.kind = 'endpoint'
    AND (a.metadata->>'env') = 'prod'
    AND f.rule_id = 'header-hsts-missing'
    AND f.status = 'open'
on_hit:
  create_finding:
    severity: medium
    title: "Prod endpoint missing HSTS"
    description: "Optional override; falls back to the rule description."
remediation: []
```

### Safety gates (enforced on every load)

The loader will refuse to accept a YAML, log a warning, and continue
serving the others if any of these fail:

1. **Forbidden keys anywhere in the document**. Any mapping key named
   `exploit`, `exploits`, `payload`, `payloads`, `shell`, `shellcode`,
   `cmd`, `command`, `injection_string`, `attack_script`,
   `reverse_shell`, `post_exploitation` fails the file.

2. **Exploitation-style text in `impact`, `description`, or
   `remediation`**. Narratives that mention `curl -`, `wget http`,
   `bash -c`, `/bin/sh`, `nc -e`, `msfvenom`, `powershell -enc`,
   `reverse shell`, `drop table`, `union select`, etc., fail the file.
   Impact text describes *outcomes*, not *procedures*.

3. **Non-SELECT SQL in a policy query**. The policy query is parsed
   with `sqlglot`; anything that isn't a single `SELECT` (or `UNION`),
   or that contains any `CREATE/DROP/ALTER/TRUNCATE/INSERT/UPDATE/
   DELETE/MERGE/COPY/GRANT/REVOKE/VACUUM/CLUSTER/REINDEX/REFRESH
   MATERIALIZED` subexpression, fails the file.

4. **Multiple statements in a policy query**. `;` inside the query is a
   hard fail even if both sides look benign — one YAML == one SELECT.

A second line of defense runs the policy SELECT inside a read-only
Postgres transaction, so even a sneaky sqlglot-parsable write would be
rejected by the server.

## Adding a new chain

1. Drop a YAML into `/policies/chains/your_rule.yaml` (or add it under
   `app/rules/chains/` in the image if it's a built-in).
2. The file-watcher picks it up within a few hundred ms. Check
   `GET /rules` to see it loaded, or `errors` if it was rejected.
3. Trigger a sweep: `curl -X POST http://correlation:8091/sweep`.
4. New chains appear at `GET /v1/chains` via the orchestrator.

## Adding a new policy

Same flow as a chain. The query should return either a column named
`id` or `asset_id` for each asset that violates the policy. The
evaluator reads that column, builds a `policy`-sourced finding per row,
and submits them via `POST /v1/findings/bulk` on the orchestrator.

## Blast-radius scoring

For each `finding_opened` event (and in the periodic sweep for every
open finding):

```
score = severity_base
      + min(len(neighbors<=2, kinds={hosts,runs,resolves_to,references}), 15)
      + (10 if finding.kev OR finding.epss >= 0.5 else 0)
      + (10 if any_ancestor_edge.metadata.public else 0)
score = clamp(score, 0, 100)
```

Severity base: `info=5, low=20, medium=50, high=75, critical=95`. The
score is merged into `findings.metadata.blast_score` via the
orchestrator PATCH endpoint.

## HTTP surface

| Verb | Path | Purpose |
|---|---|---|
| GET  | `/healthz` | liveness |
| GET  | `/readyz` | readiness (DB connected, rules loaded) |
| GET  | `/rules` | loaded chains / policies / load errors |
| POST | `/sweep` | force a full sweep of open findings and all policies |
| POST | `/recompute-blast` | re-score every open finding (`?limit=N`) |

## Events consumed

`stream:events`, consumer group `correlation`:

- `finding_opened` → chain match + blast score for the finding.
- `asset_added` → re-run all policies (new assets can satisfy them).

Other events (`finding_closed`, `cve_published`) are absorbed by the
15-minute periodic sweep rather than handled directly.
