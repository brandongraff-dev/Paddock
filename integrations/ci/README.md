# CI/CD drop-ins

Send scan results from any pipeline to Paddock. Every template does the same
two things: run a scanner, then call `paddock-ci.sh` (one small bash script) which
POSTs the report to `POST /v1/ingest`. Paddock detects the format, attributes the
findings to your source, and dedupes them against everything else it knows.

| system | file |
|---|---|
| GitLab CI | [`gitlab-ci.yml`](gitlab-ci.yml) |
| Bitbucket Pipelines | [`bitbucket-pipelines.yml`](bitbucket-pipelines.yml) |
| Azure DevOps | [`azure-pipelines.yml`](azure-pipelines.yml) |
| CircleCI | [`circleci-config.yml`](circleci-config.yml) |
| Jenkins | [`Jenkinsfile`](Jenkinsfile) |
| pre-commit | [`pre-commit-config.yaml`](pre-commit-config.yaml) (+ the root `.pre-commit-hooks.yaml`) |
| GitHub Actions | the existing `.github/actions/paddock-scan`, or the snippet in [docs/CONNECT.md](../../docs/CONNECT.md) |

## Set up in two minutes

1. In Paddock: **Integrations > Connect anything > New source**. Copy the URL and the
   token (shown once). The token can only ingest; it can be revoked or rotated, is
   rate-limited, and every upload is audit-logged.
2. In your CI system, store `PADDOCK_URL` and `PADDOCK_INGEST_TOKEN` as masked/secret
   variables.
3. Paste the template for your CI system.

Prefer a local CLI? `pip install paddock-cli` then `paddock scan --sarif` (see the CLI
docs); the templates work the same way with it.

## `paddock-ci.sh`

```
paddock-ci.sh ingest FILE [--format F] [--project P] [--asset A] [--strict] [--dry-run]
paddock-ci.sh lockfiles [--path DIR] [--project P]
paddock-ci.sh gate --fail-on high [--project P] [--soft]
paddock-ci.sh precommit FILE...
```

* `ingest` needs only `PADDOCK_INGEST_TOKEN` (or an API key with `scan`).
* `lockfiles` and `gate` reuse the logic of the GitHub Action (upload lockfiles to
  `/v1/import/lockfiles`; fetch `/v1/export/sarif` and fail on unsuppressed results at
  or above a severity) and need `PADDOCK_API_KEY`.
* The project name is detected from the CI system (`CI_PROJECT_PATH`,
  `BITBUCKET_REPO_FULL_NAME`, `BUILD_REPOSITORY_NAME`, CircleCI, Jenkins) or set
  `PADDOCK_PROJECT`.
* `PADDOCK_SOFT_FAIL=1` keeps the build green if Paddock is unreachable.
* Plain `http://` is refused unless the host is localhost or `PADDOCK_ALLOW_HTTP=1`.

## Supply-chain note

The templates download `paddock-ci.sh` from this repository at `PADDOCK_CI_REF`
(default `main`). In production pin that to a release tag or a commit SHA, or vendor
the script into your repository and call it directly.
