#!/usr/bin/env bash
# paddock-ci.sh: the one script every CI template calls.
#
#   paddock-ci.sh ingest FILE [--format F] [--project P] [--asset A] [--strict] [--dry-run]
#       POST a scanner report (SARIF, CycloneDX, SPDX, OCSF, Trivy, Grype,
#       Semgrep, Nuclei, ZAP, CSV; auto-detected) to POST /v1/ingest.
#   paddock-ci.sh lockfiles [--path DIR] [--project P]
#       Upload dependency lockfiles (same logic as the paddock-scan GitHub Action).
#   paddock-ci.sh gate --fail-on SEVERITY [--project P] [--sarif-file F] [--soft]
#       Fetch the project's SARIF and exit 1 if an unsuppressed result at or above
#       SEVERITY (low|medium|high|critical) exists. --soft: skip silently if Paddock
#       is not configured or unreachable (for commit hooks).
#   paddock-ci.sh precommit FILE...
#       Upload the given lockfiles (for the pre-commit hook; soft-fails offline).
#
# Environment:
#   PADDOCK_URL            base URL, e.g. https://paddock.example.com            (required)
#   PADDOCK_INGEST_TOKEN   per-source ingest token (pdi_...): enough for `ingest`
#   PADDOCK_API_KEY        API key: needed for `lockfiles` (scan) and `gate` (read);
#                          `ingest` also accepts it (scan)
#   PADDOCK_PROJECT        project / repository name (default: detected from the CI system)
#   PADDOCK_SOFT_FAIL=1    never fail the build because Paddock is unreachable
#   PADDOCK_CA_BUNDLE      PEM bundle for a Paddock behind a private CA
#   PADDOCK_ALLOW_HTTP=1   allow http:// (otherwise only https:// or localhost)
set -euo pipefail
set +x   # never trace: the environment holds credentials

die() { echo "paddock-ci: $*" >&2; exit "${2:-2}"; }
note() { echo "paddock-ci: $*" >&2; }

detect_project() {
  if [ -n "${PADDOCK_PROJECT:-}" ]; then printf '%s' "$PADDOCK_PROJECT"; return; fi
  if [ -n "${CI_PROJECT_PATH:-}" ]; then printf '%s' "$CI_PROJECT_PATH"; return; fi                      # GitLab
  if [ -n "${BITBUCKET_REPO_FULL_NAME:-}" ]; then printf '%s' "$BITBUCKET_REPO_FULL_NAME"; return; fi    # Bitbucket
  if [ -n "${BUILD_REPOSITORY_NAME:-}" ]; then printf '%s' "$BUILD_REPOSITORY_NAME"; return; fi          # Azure DevOps
  if [ -n "${CIRCLE_PROJECT_USERNAME:-}" ] && [ -n "${CIRCLE_PROJECT_REPONAME:-}" ]; then               # CircleCI
    printf '%s/%s' "$CIRCLE_PROJECT_USERNAME" "$CIRCLE_PROJECT_REPONAME"; return
  fi
  if [ -n "${GITHUB_REPOSITORY:-}" ]; then printf '%s' "$GITHUB_REPOSITORY"; return; fi
  if [ -n "${JOB_NAME:-}" ]; then printf '%s' "${JOB_NAME%%/*}"; return; fi                               # Jenkins
  basename "$(pwd)"
}

check_url() {
  [ -n "${PADDOCK_URL:-}" ] || die "PADDOCK_URL is not set"
  PADDOCK_URL="${PADDOCK_URL%/}"
  case "$PADDOCK_URL" in
    https://*) ;;
    http://localhost*|http://127.0.0.1*|http://\[::1\]*) ;;
    http://*) [ "${PADDOCK_ALLOW_HTTP:-}" = 1 ] || die "refusing plain http:// (credentials would travel in clear text); set PADDOCK_ALLOW_HTTP=1 to override" ;;
    *) die "PADDOCK_URL must start with https://" ;;
  esac
}

curl_common() {
  CURL_ARGS=(-sS --fail-with-body --retry 3 --retry-all-errors --max-time 600)
  [ -n "${PADDOCK_CA_BUNDLE:-}" ] && CURL_ARGS+=(--cacert "$PADDOCK_CA_BUNDLE")
  return 0
}

# Run curl; on a connection failure honour PADDOCK_SOFT_FAIL.
call() {
  local rc=0
  "$@" || rc=$?
  if [ "$rc" -ne 0 ]; then
    if [ "${PADDOCK_SOFT_FAIL:-}" = 1 ] && { [ "$rc" -eq 6 ] || [ "$rc" -eq 7 ] || [ "$rc" -eq 28 ] || [ "$rc" -eq 35 ] || [ "$rc" -eq 52 ] || [ "$rc" -eq 56 ]; }; then
      note "Paddock is unreachable (curl exit $rc); PADDOCK_SOFT_FAIL=1 so the build continues"
      exit 0
    fi
    exit "$rc"
  fi
}

summary() { # summary FILE: print a short digest of a JSON response when jq exists
  if command -v jq >/dev/null 2>&1; then
    jq -c '{source, format, status, findings_new, findings_updated, components, assets, skipped, errors: (.errors | length)}' "$1" 2>/dev/null || cat "$1"
  else
    cat "$1"
  fi
}

cmd_ingest() {
  local file="" format="" project="" asset="" strict="" dry=""
  while [ $# -gt 0 ]; do
    case "$1" in
      --format)  format="${2:?--format needs a value}"; shift ;;
      --project) project="${2:?--project needs a value}"; shift ;;
      --asset)   asset="${2:?--asset needs a value}"; shift ;;
      --strict)  strict=1 ;;
      --dry-run) dry=1 ;;
      -*)        die "ingest: unknown option $1" ;;
      *)         [ -z "$file" ] || die "ingest: only one FILE"; file="$1" ;;
    esac
    shift
  done
  [ -n "$file" ] || die "ingest: FILE is required"
  [ -f "$file" ] || die "ingest: no such file: $file"
  check_url
  [ -n "${PADDOCK_INGEST_TOKEN:-}${PADDOCK_API_KEY:-}" ] || die "set PADDOCK_INGEST_TOKEN (or PADDOCK_API_KEY)"
  curl_common
  local q="" kv
  for kv in "format=$format" "project=${project:-$(detect_project)}" "asset=$asset" "strict=${strict:+true}" "dry_run=${dry:+true}"; do
    case "$kv" in *=) continue ;; esac
    q="${q:+$q&}${kv%%=*}=$(urlenc "${kv#*=}")"
  done
  TMP_OUT="$(mktemp)"
  trap 'rm -f "${TMP_OUT:-}"' EXIT
  local hdr=(-H "Content-Type: application/octet-stream")
  if [ -n "${PADDOCK_INGEST_TOKEN:-}" ]; then hdr+=(-H "X-Paddock-Ingest-Token: ${PADDOCK_INGEST_TOKEN}"); else hdr+=(-H "X-API-Key: ${PADDOCK_API_KEY}"); fi
  call curl "${CURL_ARGS[@]}" -X POST "$PADDOCK_URL/v1/ingest?$q" "${hdr[@]}" --data-binary "@$file" -o "$TMP_OUT"
  summary "$TMP_OUT"
}

urlenc() {
  local s="$1" i c out=""
  for ((i = 0; i < ${#s}; i++)); do
    c="${s:i:1}"
    case "$c" in
      [A-Za-z0-9._~-]) out+="$c" ;;
      *) out+="$(printf '%%%02X' "'$c")" ;;
    esac
  done
  printf '%s' "$out"
}

lockfile_names='package-lock.json npm-shrinkwrap.json yarn.lock pnpm-lock.yaml requirements.txt poetry.lock Pipfile.lock Cargo.lock pom.xml Gemfile.lock go.sum go.mod'

is_lockfile() {
  local b n
  b="$(basename "$1")"
  for n in $lockfile_names; do [ "$b" = "$n" ] && return 0; done
  return 1
}

upload_lockfiles() { # upload_lockfiles PROJECT FILE...
  local project="$1"; shift
  command -v jq >/dev/null 2>&1 || die "jq is required"
  [ -n "${PADDOCK_API_KEY:-}" ] || die "set PADDOCK_API_KEY (needs the 'scan' capability)"
  check_url
  curl_common
  local n=0 f rel
  TMP_PAYLOAD="$(mktemp)"
  TMP_OUT="$(mktemp)"
  trap 'rm -f "${TMP_PAYLOAD:-}" "${TMP_PAYLOAD:-}.tmp" "${TMP_OUT:-}"' EXIT
  local payload="$TMP_PAYLOAD"
  jq -n --arg project "$project" --arg ref "${PADDOCK_SOURCE_REF:-${CI_PROJECT_URL:-${BITBUCKET_GIT_HTTP_ORIGIN:-${BUILD_REPOSITORY_URI:-}}}}" \
    '{project: $project, source_ref: (if $ref == "" then null else $ref end), files: {}}' >"$payload"
  for f in "$@"; do
    is_lockfile "$f" || continue
    [ -f "$f" ] || continue
    rel="${f#./}"
    case "$rel" in /*|*..*) note "skipping suspicious path $rel"; continue ;; esac
    jq --arg p "$rel" --rawfile c "$f" '.files[$p] = $c' "$payload" >"$payload.tmp" && mv "$payload.tmp" "$payload"
    n=$((n + 1))
  done
  if [ "$n" -eq 0 ]; then note "no lockfiles found; nothing to upload"; return 0; fi
  note "uploading $n lockfile(s) for project $project"
  call curl "${CURL_ARGS[@]}" -X POST "$PADDOCK_URL/v1/import/lockfiles" -H "X-API-Key: ${PADDOCK_API_KEY}" \
    -H "Content-Type: application/json" --data-binary "@$payload" -o "$TMP_OUT"
  jq -c '{project, components, vulnerable_components, ignored}' "$TMP_OUT" 2>/dev/null || cat "$TMP_OUT"
}

cmd_lockfiles() {
  local path="." project=""
  while [ $# -gt 0 ]; do
    case "$1" in
      --path)    path="${2:?--path needs a value}"; shift ;;
      --project) project="${2:?--project needs a value}"; shift ;;
      *)         die "lockfiles: unknown option $1" ;;
    esac
    shift
  done
  local files=()
  while IFS= read -r -d '' f; do files+=("$f"); done < <(find "$path" \
      \( -name node_modules -o -name .git -o -name vendor -o -name dist -o -name build -o -name .venv -o -name target \) -prune \
      -o -type f \( -iname package-lock.json -o -iname npm-shrinkwrap.json -o -iname yarn.lock -o -iname pnpm-lock.yaml \
      -o -iname requirements.txt -o -iname poetry.lock -o -iname Pipfile.lock -o -iname Cargo.lock -o -iname pom.xml \
      -o -iname Gemfile.lock -o -iname go.sum -o -iname go.mod \) -print0 | sort -z)
  [ "${#files[@]}" -le 200 ] || { note "more than 200 lockfiles; uploading the first 200"; files=("${files[@]:0:200}"); }
  upload_lockfiles "${project:-$(detect_project)}" "${files[@]}"
}

cmd_precommit() {
  PADDOCK_SOFT_FAIL=1
  [ -n "${PADDOCK_URL:-}" ] && [ -n "${PADDOCK_API_KEY:-}" ] || { note "PADDOCK_URL / PADDOCK_API_KEY not set; skipping"; exit 0; }
  upload_lockfiles "$(detect_project)" "$@"
}

cmd_gate() {
  local fail_on="" project="" sarif="paddock.sarif" soft=""
  while [ $# -gt 0 ]; do
    case "$1" in
      --soft)       soft=1 ;;
      --fail-on)    fail_on="${2:?--fail-on needs a value}"; shift ;;
      --project)    project="${2:?--project needs a value}"; shift ;;
      --sarif-file) sarif="${2:?--sarif-file needs a value}"; shift ;;
      *)            die "gate: unknown option $1" ;;
    esac
    shift
  done
  if [ -n "$soft" ]; then       # hook mode: never block when Paddock is not configured or not reachable
    PADDOCK_SOFT_FAIL=1
    [ -n "${PADDOCK_URL:-}" ] && [ -n "${PADDOCK_API_KEY:-}" ] || { note "PADDOCK_URL / PADDOCK_API_KEY not set; skipping"; exit 0; }
  fi
  local t
  case "$fail_on" in
    critical) t=9.0 ;; high) t=7.0 ;; medium) t=4.0 ;; low) t=0.1 ;;
    *) die "gate: --fail-on must be low|medium|high|critical" ;;
  esac
  command -v jq >/dev/null 2>&1 || die "jq is required"
  [ -n "${PADDOCK_API_KEY:-}" ] || die "set PADDOCK_API_KEY (needs 'read')"
  check_url
  curl_common
  call curl "${CURL_ARGS[@]}" -G "$PADDOCK_URL/v1/export/sarif" --data-urlencode "project=${project:-$(detect_project)}" \
    -H "X-API-Key: ${PADDOCK_API_KEY}" -o "$sarif"
  local n
  n="$(jq --argjson t "$t" '[.runs[] as $r | $r.results[]
        | select(((.suppressions // []) | length) == 0)
        | ($r.tool.driver.rules[.ruleIndex].properties["security-severity"] // "0" | tonumber)
        | select(. >= $t)] | length' "$sarif")"
  if [ "$n" -gt 0 ]; then
    note "FAIL: $n unsuppressed result(s) at or above '$fail_on' (see $sarif)"
    exit 1
  fi
  note "ok: no unsuppressed results at or above '$fail_on'"
}

main() {
  local sub="${1:-}"
  [ -n "$sub" ] || die "usage: paddock-ci.sh ingest|lockfiles|gate|precommit ..."
  shift
  case "$sub" in
    ingest)    cmd_ingest "$@" ;;
    lockfiles) cmd_lockfiles "$@" ;;
    gate)      cmd_gate "$@" ;;
    precommit) cmd_precommit "$@" ;;
    -h|--help|help) sed -n '2,/^set -euo/p' "$0" | sed '$d' | sed 's/^# \{0,1\}//' ;;
    *)         die "unknown command: $sub" ;;
  esac
}

main "$@"
