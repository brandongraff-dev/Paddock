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
