# Contributing to Paddock

Thanks for wanting to help. Paddock is a **defensive, detection-only**
Attack Surface Management platform, and that framing shapes what we will and
won't merge. Please skim the [README](README.md) and [SECURITY.md](SECURITY.md)
before you start — especially the "Hard rules" and §6 ("Detection, not
exploitation").

- [Ground rules](#ground-rules)
- [Project shape](#project-shape)
- [Dev setup](#dev-setup)
- [Running the tests](#running-the-tests)
- [The one rule: tests NEVER touch a live database](#the-one-rule-tests-never-touch-a-live-database)
- [The integration harness](#the-integration-harness)
- [Linting & formatting](#linting--formatting)
- [Making a change](#making-a-change)
- [Pull requests](#pull-requests)
- [Contributor License Agreement (CLA)](#contributor-license-agreement-cla)

## Ground rules

1. **Detection only.** We will not merge auto-exploitation, credential attacks,
   or evasion. This isn't negotiable — it's what makes the tool legal and safe
   to run. See the PR template's "Safety gate".
2. **Scope is sacred.** Nothing may send traffic to a host outside the
   `scope_entries` allowlist. If you touch the egress/scope path, the burden of
   proof that the invariant still holds is on the PR.
3. **Be honest in docs.** We'd rather ship a documented gap than an oversold
   feature. The "Status" section of the README and §10 of SECURITY.md are
   features, not embarrassments.

## Project shape

A FastAPI **orchestrator** owns the database and the API; everything else is a
small service that talks to it. See [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md)
for the full service map and data flow, and the per-service notes in `docs/`
(`ORCHESTRATOR_NOTES.md`, `PASSIVE_NOTES.md`, `CORRELATION_NOTES.md`, …).
The inter-service contract lives in [`docs/CONTRACTS.md`](docs/CONTRACTS.md) —
read it before changing anything shared.

```
orchestrator/        FastAPI: API, scope, auth/RBAC/ABAC, audit, dispatch
workers/passive/     passive discovery (CT, DNS, Shodan, Wayback, …)
workers/active/      authorized polite probing (http, tls, naabu, nuclei, …)
intel/               NVD / EPSS / KEV ingest + CPE matching
correlation/         chains, policies-as-code, blast radius, attack paths
sca/ codeanalysis/   dependency + first-party code analysis
mlrisk/ changewatch/ risk ranking, surface-change detection
triage/ ontology/    ticketing/owners, typed-object projection
threatintel/ brain/  STIX/TAXII IOC fusion, LLM triage + NL query
graphsync/           Postgres -> Neo4j graph projection
dashboard/           React + Vite + TypeScript UI
schema/              SQL applied on Postgres init (the DB is the authority)
policies/            YAML chain + policy rules (hot-reloaded)
hardening/           integration harness, real-target FP harness, ops audit
```

## Dev setup

You need **Docker + Docker Compose**. For running a single service's test suite
you also need **Python 3.12+**; for the dashboard, **Node 20+**.

Bring the whole stack up in the dev profile and seed a demo graph:

```bash
cp .env.example .env         # dev defaults are fine as-is
make quickstart              # build + up + seed the acme-demo graph
# dashboard:    http://localhost:3000
# API docs:     http://localhost:8080/docs
```

`make up` runs the **dev profile** (`docker-compose.override.yml` is auto-merged):
every service port is published to the host and `AUTH_MODE=dev` injects a
synthetic admin so you aren't blocked by auth while hacking. The **hardened
profile** (`docker compose -f docker-compose.yml …`) closes ports and enforces
auth — run `make harden-check` to self-audit it.

Useful targets (`make help` lists them all):

```bash
make logs-orchestrator   # tail one service
make status              # /healthz across services
make seed-scope          # load the safe default scan scope
make down                # stop (keeps volumes);  make nuke  wipes volumes
```

## Running the tests

Each Python service is independently installable and tested. Install it with
its test extra and run `pytest` from its directory:

```bash
# most services use the `test` extra:
cd correlation && pip install -e ".[test]" && pytest -q

# a few use `dev` instead (orchestrator, intel, workers/active):
cd orchestrator && pip install -e ".[dev]" && pytest -q
```

`make test` runs the core suites via Docker; the dashboard:

```bash
cd dashboard && npm ci && npx vitest run
npx tsc -b                  # type-check
```

CI (`.github/workflows/ci.yml`) runs every service's suite in a matrix, the
dashboard job, and `ruff check`. A Postgres 16 service container is provided to
the Python legs as `TEST_DATABASE_URL`.

## The one rule: tests NEVER touch a live database

**This is the rule we care about most.** It exists because a test suite once
pointed at a live database and truncated real data. Don't be the second
incident.

- DB-backed suites read **`TEST_DATABASE_URL`** (falling back to `DATABASE_URL`)
  and **skip cleanly** when it's unset or unreachable. They apply schema and
  freely `TRUNCATE` — so that URL must only ever point at a **disposable** DB.
- The orchestrator suite uses **`pytest-postgresql`**, which spins up its own
  throwaway Postgres instance and a fresh database **per test**. It never reads
  your `DATABASE_URL`. `pg_ctl` refuses to run as root (e.g. in dev
  containers); there, start a disposable server as another user and point the
  suite at it with `ORCH_TEST_PG=127.0.0.1:<port>[:<user>]` — it still creates
  and drops its own database per test.
- Scope changes must keep the differential fuzzer green:
  `pip install ada-url && python hardening/stress_scope.py --n 1000000`.
- When you add a DB test, follow the existing `conftest.py` pattern (skip
  without a test DSN; create/own your data; clean up after). **Never** hardcode
  a DSN, and never let a suite connect to the compose `postgres` service that's
  holding demo/real data.

If your change makes a test require a database, it must honor this contract. The
PR template has a checkbox for it; we will hold you to it.

## The integration harness

`hardening/integration_test.py` (run via `make integration`) is **not** a unit
test. It drives the full running stack end-to-end and asserts the cross-service
contracts that past bugs kept breaking (missing `asset_value`/`blast_score`,
bad envelopes, unwired services). It **must** run against a disposable/demo
database only, and it never truncates anything.

```bash
make quickstart       # stack up + demo graph seeded (gives the harness a surface)
make integration      # drives correlation, sca, codeanalysis, changewatch,
                      # triage, mlrisk, ontology, threatintel, brain, audit chain
```

It prints a PASS/FAIL/SKIP table and exits non-zero on any hard FAIL. There's
also `make realrun` — an **authorized-scope-only** real-target run against
`scanme.nmap.org` with a crude false-positive measurement (see
[`hardening/RUNBOOK.md`](hardening/RUNBOOK.md)). Do not point it anywhere you
aren't authorized to scan.

## Linting & formatting

```bash
ruff check .                 # the enforced CI rule set (see ruff.toml)
ruff check --select ALL .    # the broader set (not yet enforced; fix what you touch)
ruff format .                # formatter
```

CI enforces a focused, high-signal ruff rule set (real bugs: syntax, undefined
names, bad comparisons). The broader style/import rules aren't enforced yet
because the codebase predates a formatter pass — please don't reformat files
you aren't otherwise changing (it buries the real diff).

## Making a change

1. Open (or claim) an issue so we don't duplicate work.
2. Branch from `main`.
3. Keep the change focused; add or update tests.
4. If you touch a shared schema or an inter-service contract, update
   `docs/CONTRACTS.md` and every dependent service in the same PR.
5. Update docs when behavior, flags, or contracts change.

## Pull requests

Fill in the PR template, including the **Safety gate** and the **never-touch-
the-live-DB** checkboxes. Green CI (service suites + dashboard + lint) is
required. A maintainer will review; expect questions on anything near the scope,
egress, or auth boundaries — that scrutiny is the point.

By contributing, you agree your contributions are licensed under the project's
[AGPL-3.0](LICENSE).

## Contributor License Agreement (CLA)

Before your first pull request can be merged you'll be asked to sign the
[CLA](CLA.md) — a one-line PR comment, checked by the CLA Assistant bot
(`.github/workflows/cla.yml`). Companies contributing on behalf of employees
sign the Corporate CLA once.

**Why:** Paddock is AGPL-3.0, and it is *also* offered under commercial
licenses (see [docs/EDITIONS.md](docs/EDITIONS.md)) — that is what pays for
sustained full-time work on the open-source code. The project can only offer
code under a second license if it has the right to, and it can't relicense
contributions it doesn't have rights to. The CLA grants that right while you
**keep your copyright**, and it commits the project to keeping every accepted
contribution available under the AGPL (or another OSI-approved license). It
also adds an explicit patent grant, which protects every user.

If you can't sign a CLA, you can still help: open issues, review PRs, and
write detailed bug reports — those don't need one.
