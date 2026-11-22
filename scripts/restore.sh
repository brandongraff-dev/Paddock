#!/usr/bin/env bash
# Paddock Postgres restore: verify checksum -> decrypt -> pg_restore.
# See docs/OPERATIONS.md "Restore drill".
#
#   scripts/restore.sh backups/paddock-asm-20260101T000000Z.dump[.age|.gpg]
#   make restore FILE=backups/...
#
# Target (RESTORE_VIA, default auto -- same rules as backup.sh):
#   local    pg_restore into RESTORE_DATABASE_URL (else DATABASE_URL).
#   compose  `docker compose exec -T postgres pg_restore` into the bundled DB.
#
# Safety:
#   * The .sha256 next to the file MUST match (RESTORE_SKIP_VERIFY=1 to skip,
#     e.g. when the checksum file was lost -- think twice).
#   * If the target database already has tables you must confirm with
#     RESTORE_CONFIRM=yes (or --yes): the restore DROPS and recreates every
#     object in the dump (pg_restore --clean --if-exists).
#   * The whole restore runs in ONE transaction (--single-transaction
#     --exit-on-error): it either fully succeeds or leaves the target as it was.
#   * Stop the orchestrator and workers first (writes during a restore are lost).
#
# Decryption: AGE_IDENTITY=<key file> for .age; gpg uses your keyring for .gpg.
# After a restore, run the migrations (`docker compose run --rm migrate` or
# `python -m app.migrate up`) so an older backup is brought forward to the
# running code's schema, then verify the audit chain (GET /v1/audit/verify).
set -euo pipefail
umask 077

log() { printf '%s restore: %s\n' "$(date -u +%H:%M:%S)" "$*" >&2; }
die() { log "ERROR: $*"; exit 1; }
pg_dsn() { local u=${1:-}; u=${u/postgresql+asyncpg:/postgresql:}; u=${u/postgres+asyncpg:/postgres:}; printf '%s' "$u"; }

FILE=""
for a in "$@"; do
  case $a in
    --yes|-y) RESTORE_CONFIRM=yes ;;
    -h|--help) sed -n '2,27p' "$0"; exit 0 ;;
    *) FILE=$a ;;
  esac
done
[[ -n $FILE ]] || die "usage: restore.sh <backup file> [--yes]"
[[ -f $FILE ]] || die "no such file: $FILE"

RESTORE_VIA=${RESTORE_VIA:-auto}
COMPOSE=${COMPOSE:-docker compose}
PGDB=${PGDB:-asm}
PGUSER_COMPOSE=${PGUSER_COMPOSE:-asm}
TARGET=$(pg_dsn "${RESTORE_DATABASE_URL:-${DATABASE_URL:-}}")
if [[ $RESTORE_VIA == auto ]]; then
  if [[ -n $TARGET || -n ${PGHOST:-} ]]; then RESTORE_VIA=local; else RESTORE_VIA=compose; fi
fi

# 1. checksum
if [[ ${RESTORE_SKIP_VERIFY:-0} != 1 ]]; then
  [[ -f $FILE.sha256 ]] || die "missing $FILE.sha256 (RESTORE_SKIP_VERIFY=1 to override)"
  (cd "$(dirname "$FILE")" && sha256sum --quiet -c "$(basename "$FILE").sha256") \
    || die "checksum mismatch for $FILE -- refusing to restore"
  log "checksum OK"
fi

# 2. decrypt (to a private temp file, removed on exit)
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT
dump=$FILE
case $FILE in
  *.age)
    command -v age >/dev/null || die "'age' not installed"
    [[ -n ${AGE_IDENTITY:-} ]] || die "set AGE_IDENTITY=<age identity file> to decrypt"
    age --decrypt -i "$AGE_IDENTITY" -o "$work/db.dump" "$FILE"; dump=$work/db.dump ;;
  *.gpg)
    command -v gpg >/dev/null || die "'gpg' not installed"
    gpg --batch --yes --decrypt --output "$work/db.dump" "$FILE"; dump=$work/db.dump ;;
esac

run_sql() {
  if [[ $RESTORE_VIA == local ]]; then
    psql "$TARGET" -XAtqc "$1"
  else
    $COMPOSE exec -T postgres psql -U "$PGUSER_COMPOSE" -d "$PGDB" -XAtqc "$1"
  fi
}

# 3. refuse to clobber a non-empty database without confirmation
tables=$(run_sql "SELECT count(*) FROM pg_tables WHERE schemaname = 'public'")
if [[ $tables -gt 0 && ${RESTORE_CONFIRM:-} != yes ]]; then
  die "target database has $tables tables; it will be OVERWRITTEN. Re-run with RESTORE_CONFIRM=yes (or --yes)"
fi
[[ -f $FILE.meta ]] && log "backup meta: $(tr '\n' ' ' <"$FILE.meta")"

# 4. restore, atomically
if [[ $RESTORE_VIA == local ]]; then
  where=$(printf '%s' "${TARGET%%\?*}" | sed -E 's#//[^@]*@#//***@#')  # never log a password
else
  where="compose:$PGDB"
fi
log "restoring into $where"
opts=(--clean --if-exists --no-owner --no-privileges --single-transaction --exit-on-error)
if [[ $RESTORE_VIA == local ]]; then
  # A pg_restore newer than the target server (e.g. client tools 17+ against
  # a 16 server) replays session settings the server doesn't know
  # (SET transaction_timeout), and the restore fails. In that case render the
  # archive to SQL, drop only those settings, and apply it with psql in ONE
  # transaction that stops at the first error, which keeps the all-or-nothing
  # guarantee. RESTORE_VIA_SQL=1 forces this path.
  client_major=$(pg_restore --version | grep -oE '[0-9]+' | head -1)
  server_major=$(( $(run_sql "SHOW server_version_num") / 10000 ))
  if [[ ${RESTORE_VIA_SQL:-0} == 1 || $client_major -gt $server_major ]]; then
    log "pg_restore $client_major is newer than the server ($server_major): restoring via SQL"
    pg_restore --clean --if-exists --no-owner --no-privileges -f - "$dump" \
      | grep -vE '^SET (transaction_timeout) = ' \
      | psql "$TARGET" -X -q -v ON_ERROR_STOP=1 --single-transaction -f - >/dev/null
  else
    pg_restore "${opts[@]}" --dbname "$TARGET" "$dump"
  fi
else
  $COMPOSE exec -T postgres pg_restore "${opts[@]}" -U "$PGUSER_COMPOSE" -d "$PGDB" <"$dump"
fi

last=$(run_sql "SELECT COALESCE(max(filename),'(none)') FROM schema_migrations" 2>/dev/null || echo "(no schema_migrations)")
audit=$(run_sql "SELECT count(*) FROM audit_log" 2>/dev/null || echo "?")
log "restore complete: last migration $last, audit_log rows $audit"
log "next: run migrations (docker compose run --rm migrate | python -m app.migrate up), start the stack, then GET /v1/audit/verify"
