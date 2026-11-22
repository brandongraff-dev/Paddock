# paddock CLI

`paddock` is the free, local entry point to Paddock: run one command on your own repo and get real
problems and ready-made fixes in under a minute, with no server. Results can optionally be sent to a
Paddock server later (see [Upload](#upload-opt-in)).

It is a thin, dependency-free (stdlib only, Python 3.11+) front end over engines that already exist
in this repository. Nothing is reimplemented that an engine provides.

| Concern | Reused from | How |
|---|---|---|
| Lockfile/manifest parsing, typosquat risk, OSV mapping | `sca/app` (`parsers`, `risk`, `osv`) | loaded as a library |
| SAST taint rules, hard-coded credentials | `codeanalysis/app/sast` | `run_sast` |
| SARIF 2.1.0 | `orchestrator/app/standards.sarif_log` | same writer as `GET /v1/export/sarif` |
| Diff generators, deterministic gate, rule verifier, injection scan | `remediation/app` | `generators`, `gate`, `verify`, `injection` |
| Upload payloads | `sca` `build_sca_finding`, `codeanalysis` `build_sast_finding` | `POST /v1/findings/bulk` |
| Crown-jewel routes, minimum fix set, change gate | `correlation/app/engine/wargame` | `parsers`, `topology`, `Environment.reachability`, `mincut`, `changegate` |

Each service ships a package named `app`, so the CLI loads them under private aliases
(`paddock_cli/engines.py`) instead of importing them normally. In a checkout it reads the service
directories; a built wheel carries a generated copy in `paddock_cli/_vendor` (`setup.py`).
The only engine change: `sca/app/osv.py` and `sca/app/orchestrator.py` import `aiohttp` optionally, so
their pure helpers work without it. Service behaviour and tests are unchanged.

## Install

```bash
pipx run --spec paddock-cli paddock scan     # no install
pip install ./cli                            # from a checkout (PyPI publishing is not set up yet)
docker build -f cli/Dockerfile -t paddock .  # context = repo root
docker run --rm -v "$PWD:/src" paddock scan
```

## scan

```bash
paddock scan [PATH] [--json | --sarif FILE] [--fail-on high] [--offline] [--only deps,secrets,code,config]
```

* Output is grouped (dependencies, secrets, code, configuration), severity-coloured, and every finding
  says **why it matters** and how to fix it.
* `--json` prints a machine-readable report; `--sarif FILE` (or `-`) writes SARIF 2.1.0 for GitHub code scanning.
* `--fail-on LEVEL` exits `1` when anything at or above LEVEL exists (default: never fail).
* `--offline` never touches the network: only the on-disk OSV cache (`~/.cache/paddock`, or
  `PADDOCK_CACHE_DIR`) is used, and packages not in it are reported as unchecked rather than clean.
  Online, a stale cache entry is used if OSV is unreachable, and the report says so.
* Inside a git work tree the file list is `git ls-files` (so `.gitignore` is honoured); otherwise common
  build/vendor directories are skipped. `--exclude GLOB` adds more; `--no-git` forces a directory walk.
* `--semgrep` prefers Semgrep when installed (`pip install paddock-cli[semgrep]`); the default is the
  bundled taint scanner, which is fast and fully offline.
* Go: go.sum lists every version ever downloaded, so entries superseded in `go.mod` are ignored and
  `go.mod` requires are scanned too.

Secret values are redacted everywhere (terminal, JSON, SARIF, upload, PR text).

## fix

```bash
paddock fix [PATH] [--yes] [--patch out.diff] [--pr] [--allow-major]
```

Fixes are generated **deterministically by code**. No model writes any edit. `fix` scans, plans fixes,
checks each one, prints the combined diff, asks for confirmation, applies, **re-runs the scan** and prints
`verified: N of M fixed`.

| Fix | Applies to | Produced by |
|---|---|---|
| Dependency upgrade to the nearest version that clears every advisory | `requirements.txt`, `package-lock.json` (v1-v3), `go.mod`, `pom.xml` | generator for requirements; CLI edit for the rest |
| Secret to environment variable, with a `.env.example` entry and `.env` in `.gitignore` | Python and JS/TS `NAME = "literal"` assignments | CLI edit |
| Disable TLS 1.0/1.1; add HSTS | nginx `*.conf` | `remediation` generators |

Choosing the version: for each advisory take the nearest `fixed` version above yours; the answer is the
highest of those. The target is then looked up in OSV itself and, if it is still vulnerable, the CLI hops
again (up to four times). Upgrades that cross a major version are listed but skipped unless `--allow-major`.
Maven `-jre`/`-android` flavours and Go's `v` prefix are preserved. If `package.json` pins a range that
excludes the fix, the fix is left to you (editing the lockfile alone would make `npm ci` fail).

Safety layers, all before anything is written:

1. **Gate.** Every dependency and config diff passes `remediation/app/gate.check` and the rule verifier
   `verify.verify` (allow-listed files, only the expected version/directive changes, no new network calls or
   scripts, size caps). A refused fix is shown with the reason and never offered.
   Structured manifests (`package-lock.json`, `pom.xml`) keep the package name on a neighbouring line, so the
   verifier's "name on an added line" reason is expected there; the gate's own context check still applies.
   For npm the gate sees the pure version edit; the `resolved` URL is then repointed and the stale
   `integrity` dropped for that entry (otherwise `npm ci` would install the old tarball).
2. **Secret rewrite gate.** The remediation gate hard-denies source-code files by design, so the secret fix
   cannot pass it. It is checked by a stricter CLI-local gate instead: exactly one source line may change,
   the value may not survive anywhere in the diff, `.env.example` may only gain `KEY=` lines, `.gitignore`
   only `.env`, and Python must still parse.
3. **Freshness.** Files are re-read before writing; if one changed since the plan, nothing is written.
   Writes stay inside the scanned directory.
4. **Re-verification.** The scan is re-run; a fix counts only when its findings are gone and no finding
   remains for that package. Offline, new versions cannot be checked and are reported `unverified`.

Things the CLI deliberately leaves to you and says so: taint bugs (SQL/command injection), secrets in other
file types, `go.sum` refresh (`go mod tidy`), `poetry.lock`/`yarn.lock`/`Cargo.lock`/`Gemfile.lock` edits,
and **rotating a leaked secret** (it stays in git history).

* `--patch FILE` writes the diff (`git apply FILE`) and applies nothing unless `--yes` is also given.
* Without a terminal and without `--yes` it prints the diff and refuses to apply.
* `--json` is a dry run unless `--yes`.

### Pull requests

```bash
GITHUB_TOKEN=... paddock fix --pr [--draft] [--repo OWNER/NAME]
```

Creates a new branch `paddock/fix-<date>-<hash>`, applies and verifies, commits only the touched files,
pushes `HEAD:refs/heads/<that branch>`, opens a PR whose body explains each fix (advisories, files, why it
matters, gate result, notes, verification), and returns your checkout to the branch it started on.
It **never pushes to the default branch and never merges or enables auto-merge** (there is no such call in the
code). It refuses if the touched files have uncommitted changes. The token is read from `GITHUB_TOKEN` only,
handed to git through the environment, and never written to config, logs or the PR. The PR text goes through
the remediation injection scanner first. Needs `contents: write` and `pull_requests: write`.

## init

`paddock init` writes `.github/workflows/paddock.yml` (scan, `--sarif`, `--fail-on high`, upload to code
scanning with `if: always()`, weekly schedule) and `.pre-commit-config.yaml` (offline secrets and code check).
Existing files are never overwritten (`--force` re-creates the workflow); an existing pre-commit config gets
the snippet printed instead of being edited.

## wargame

```bash
paddock wargame init                                  # write an example project to try
paddock wargame check [--file wargame.toml] [--json]
paddock wargame plan PLAN.json [--file wargame.toml] [--flows FILE] [--json | --markdown] [--strict]
```

Wargame's "aha", locally and without a server: describe the segments that matter, point at your
firewall and cloud config exports, and `check` works backward from each crown jewel to show every
route that reaches it, **labelled hop by hop with the evidence behind it**, plus the cheapest set of
changes that cuts every route. `plan` runs the same model against a `terraform show -json` plan and
says whether the change opens a route or breaks live traffic. It reads files and prints; it sends no
packet, applies nothing and never runs an exploit (the engine's rules, see
[WARGAME_ENGINE.md](WARGAME_ENGINE.md)). Engine reference and evidence ladder: same document.

### wargame.toml

`paddock wargame init` writes a commented example (guest Wi-Fi to a smart fridge to the POS controller
to the payments database) plus tiny sample configs under `wargame/`, so `check` works immediately.
Existing files are never overwritten (`--force` does). Paths are relative to the project file.

| Section | Keys | Meaning |
|---|---|---|
| `[project]` | `name` | label in output (default: directory name) |
| `[[segment]]` | `id`, `cidrs`, `role`, `jewel_kind`, `reason` | a network that matters. `role` is `entry` (where an attacker could start), `crown_jewel` (must stay unreachable) or `intermediate` (default). At least one entry and one crown jewel are required |
| `[[source]]` | `vendor`, `path`, `id_prefix`, `sg_members` | a config export. `vendor`: `fortinet`, `cisco_asa`, `paloalto` (device config text), `aws` (`describe-security-groups` or `describe-network-acls` JSON), `aws_routes` (`describe-route-tables` JSON; a hop with no route is dropped). `id_prefix` disambiguates two devices that reuse rule set names; `sg_members = { "sg-1" = ["10.0.0.0/24"] }` resolves SG-to-SG references (aws) |
| `[zones]` | `name = "segment-id"` | a firewall zone or interface to the segment behind it |
| `[subnets]` | `name = "segment-id"` | an AWS subnet or ENI to its segment |
| `[[edge]]` | `from`, `to`, `ruleset`, `port`, `evidence`, `note` | a declared adjacency. `ruleset` names a rule set from a source (an unknown name is an error, never a silent "closed"). With none, the edge is an ungoverned adjacency, labelled **inferred**. `port` is `tcp/5432`, `udp/53`, `tcp/8000-8100` or `any`. `evidence = "observed"` marks an ungoverned edge you have seen traffic on |
| `[flows]` | `file`, `format` | observed traffic (Zeek `conn.log` JSON lines, firewall allow logs, generic JSON; `format` is `auto`, `generic`, `zeek` or `firewall`). Real flows add *observed* evidence and `plan` uses them to list the live flows a change would break |

Rule sets whose two sides both resolve through `[zones]`/`[subnets]` are wired into the model
automatically (Fortinet and Palo Alto zone pairs, AWS subnets); anything else is declared with `[[edge]]`.

### check

Prints the board line (closure **always** with its coverage caveat), every open route with each hop's
evidence, the cheapest fix set with `cuts every route: yes/no`, and a **"what we couldn't prove"**
section: conditional rules (FQDN, App-ID, unresolved objects, treated as reachable), parser gaps and
routing assumptions. A conditional or inferred hop is printed `UNPROVEN`; such a route counts as open.

```text
  33.3% of routes to crown jewels are proved closed, over a model whose coverage is not yet
  measured; 2 routes remain open.

  OPEN ROUTES (2 across 2 entry/jewel pairs)
    1. guest-wifi -> iot -> pos -> payments-db   proved
      guest-wifi -> iot          observed traffic + proved by config   fortinet:guest>iot:1
      iot        -> pos          proved by config   fortinet:iot>pos:2
      pos        -> payments-db  observed traffic + proved by config   tcp/5432  sg-0paymentsdb#in0
    2. vendor-support -> pos -> payments-db   UNPROVEN
      vendor-support -> pos          CONDITIONAL, UNPROVEN   fortinet:wan>pos:3
        -> depends on runtime state the config cannot prove (FQDN, App-ID, unresolved object)
      pos            -> payments-db  observed traffic + proved by config   tcp/5432  sg-0paymentsdb#in0

  CHEAPEST FIX SET (cost 1, exact search)
    1. tighten rule set sg-0paymentsdb so pos can no longer reach payments-db
       cuts 2 of 2 open routes · cloud_policy · rule sg-0paymentsdb#in0
       cuts every route: yes
```

Exit codes: `0` no open route reaches a crown jewel, `1` at least one does, `2` bad input (the message
says which key or file). `--json` prints schema `paddock.wargame.check/1`. Fix costs come from the
engine's cost classes: a rule change is cheaper than a segmentation change. With more than 24 candidate
changes the search is greedy and says so instead of calling the result minimal.

### plan

```text
  This change opens a route to payments-db (from branch-office).

  ROUTES OPENED
   + branch-office -> payments-db
       branch-office -> payments-db  proved by config   aws_security_group_rule.branch_to_payments_db
```

or "This change would break 2 live flows", with the flows listed. The verdict, plainly:

| Verdict | Meaning | Exit |
|---|---|---|
| `safe` | no route to a crown jewel opens and no observed flow breaks | `0` |
| `opens_route_to_crown_jewel` | an entry/jewel pair that was closed now has a route | `1` |
| `breaks_live_flows` | traffic seen in `[flows]`/`--flows` would be denied | `1` |
| `opens_and_breaks` | both | `1` |

It understands `aws_security_group_rule`, `aws_vpc_security_group_{ingress,egress}_rule` and
`aws_network_acl_rule`. Anything else in the plan, and any change to a rule set that is not in the
model, is listed under "what we couldn't prove" rather than being ignored (`--strict` also fails on
those). Without observed flows the live-flow check cannot run, and the output says so. No colour unless
stdout is a terminal (`NO_COLOR`/`FORCE_COLOR` as for `scan`). `--json` prints `paddock.wargame.plan/1`;
`--markdown` prints a PR-comment sized report.

Limitation today: the Terraform parser identifies rules by their Terraform address, so a plan that
*modifies or deletes* a rule that came from an exported config cannot be matched to it and is reported
as not modelled. Added rules, the case that opens routes, are matched by security group / NACL id.

### In CI (GitHub Actions)

An example for a Terraform repository; nothing like it is installed for you (`paddock init` is for
`scan`). Keep `wargame.toml` and the config exports in the repo or refresh them in an earlier step.

```yaml
name: wargame
on: pull_request
permissions:
  contents: read
  pull-requests: write
jobs:
  plan-check:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: hashicorp/setup-terraform@v3
        with: { terraform_wrapper: false }
      - uses: actions/setup-python@v5
        with: { python-version: "3.12" }
      - run: pip install ./cli            # or: pipx install paddock-cli, once published
      - run: |
          terraform init -input=false
          terraform plan -input=false -out=tfplan
          terraform show -json tfplan > plan.json
      - name: Would this change open a route to a crown jewel?
        run: paddock wargame plan plan.json --markdown > wargame-comment.md
      - name: Comment on the PR
        if: always()
        env:
          GH_TOKEN: ${{ github.token }}
        run: gh pr comment ${{ github.event.pull_request.number }} --body-file wargame-comment.md --edit-last || gh pr comment ${{ github.event.pull_request.number }} --body-file wargame-comment.md
```

The `plan` step fails the job (exit `1`) when the change is not safe, so make it a required check to
block the merge. Use `--json` instead of `--markdown` to feed another tool.

## Upload (opt-in)

```bash
paddock login --server https://paddock.internal      # checks /healthz (+ /v1/auth/me if a key is set)
PADDOCK_API_KEY=pak_... paddock upload [PATH] --project my-service
```

`upload` is the only command that contacts a Paddock server, and it never runs implicitly: `scan` and `fix`
make no server calls. It posts to the existing `POST /v1/findings/bulk` (the endpoint the SCA and codeanalysis
services use), as `sca`, `sast`, `secret_scan` and `policy` findings attached to a `repository` asset named
after the project. The key is read from `PADDOCK_API_KEY` and never saved (`login` stores only the server URL,
mode 0600). Plain `http://` is refused except for localhost. There is no SBOM or code-finding ingest endpoint
in the orchestrator today (those routers are read-only), so the findings API is the whole upload surface.

## Limits

* Detection is only as good as the engines: the bundled taint scanner is intentionally light (no
  inter-procedural analysis); use `--semgrep` for more.
* Version ordering is a pragmatic comparison across semver/PEP 440/Maven/Go, not a full implementation of each.
* The Docker image and PyPI publishing are described but not exercised by this repository's CI beyond a build.
