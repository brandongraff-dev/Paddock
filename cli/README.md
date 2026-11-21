# paddock-cli

Find real problems in your repo, and get the fix, in under a minute. No server, no account, no
dependencies beyond Python 3.11+.

```text
$ paddock scan
  CRITICAL  org.apache.logging.log4j:log4j-core 2.14.1: 2 known vulnerabilities   java/pom.xml:9
            why  This ships in your build and the flaw is public, so attackers can find ...
            fix  upgrade to 2.16.0  (paddock fix)
  ...
  10 findings:  2 CRITICAL  4 HIGH  3 MEDIUM  1 LOW
  ✔ 8 of 10 can be fixed automatically: run paddock fix to see the diff first
```

## 30-second quickstart (record this)

```bash
pipx run --spec paddock-cli paddock scan      # 1. what is wrong (deps, secrets, code, config)
paddock fix                                   # 2. show the diff, ask, apply   -> "verified: 8 of 8 fixed"
paddock fix --pr                              # 3. or open a pull request (GITHUB_TOKEN), never merged
paddock init                                  # 4. keep it that way: GitHub Action + pre-commit hook
```

`pipx run paddock-cli scan` works too (the package also installs a `paddock-cli` script).
From a checkout: `pip install ./cli`. Docker: `docker build -f cli/Dockerfile -t paddock .` then
`docker run --rm -v "$PWD:/src" paddock scan`.

## What it checks

| | engine reused | notes |
|---|---|---|
| Vulnerable dependencies | `sca/` parsers + OSV | npm, PyPI, Go, Maven, crates.io, RubyGems lockfiles/manifests |
| Malicious / look-alike packages | OSV `MAL-` advisories, `sca/risk/typosquat` | |
| Code bugs (SQLi, command injection, path traversal, SSRF, unsafe deserialisation, weak crypto) | `codeanalysis/` taint scanner (Semgrep with `--semgrep`) | Python, JS/TS, Go |
| Secrets | `codeanalysis/` + token formats and config-file credentials | values are never printed or uploaded |
| Misconfiguration | nginx `ssl_protocols`, missing HSTS | the cases the fix generators can repair |

OSV answers are cached in `~/.cache/paddock` (`PADDOCK_CACHE_DIR`). `--offline` uses only the cache.

## Commands

```text
paddock scan [PATH]   --json  --sarif FILE  --fail-on {low,medium,high,critical}  --offline
                      --only deps,secrets,code,config  --exclude GLOB  --all  -q
paddock fix  [PATH]   -y/--yes  --patch FILE  --pr [--draft] [--repo OWNER/NAME]  --allow-major
paddock init [PATH]   --force  --no-workflow  --no-pre-commit
paddock login --server URL        # remembers the server; the key stays in $PADDOCK_API_KEY
paddock upload [PATH] --server URL [--project NAME]    # opt-in; never runs implicitly
```

Exit codes: `0` ok, `1` findings at or above `--fail-on` (or, for `fix`, something not verified),
`2` usage or runtime error. Colour follows a TTY; `NO_COLOR` disables it, `FORCE_COLOR` forces it.

Full documentation: [docs/CLI.md](../docs/CLI.md).

## Develop

```bash
cd cli && python -m pytest -q        # no network, no extra dependencies (pyyaml optional)
```
