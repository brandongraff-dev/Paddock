#!/usr/bin/env bash
# Paddock Postgres backup: pg_dump custom format + sha256 + optional
# encryption (age or gpg) + retention.  See docs/OPERATIONS.md "Backups".
#
#   scripts/backup.sh                    # or: make backup
#
# Where the dump comes from (BACKUP_VIA, default auto):
#   local    pg_dump on this host against DATABASE_URL (or PG* env vars).
#            Use this for external/managed Postgres and from a k8s CronJob.
#   compose  `docker compose exec -T postgres pg_dump` (the bundled database).
#   auto     local if DATABASE_URL or PGHOST is set, else compose.
#
# Environment:
#   BACKUP_DIR              output directory            (default ./backups)
#   BACKUP_RETENTION_DAYS   delete older backups        (default 14; 0 = keep all)
#   BACKUP_MIN_KEEP         never prune below N newest  (default 3)
#   BACKUP_ENCRYPT          none | age | gpg            (default none)
#   AGE_RECIPIENTS_FILE / AGE_RECIPIENT   age public key(s)   (BACKUP_ENCRYPT=age)
#   GPG_RECIPIENT           gpg key id / email          (BACKUP_ENCRYPT=gpg)
#   COMPOSE                 compose command              (default "docker compose")
#   PGDB / PGUSER_COMPOSE   database / role inside the compose postgres (asm/asm)
#
# Output (all mode 0600 in a 0700 dir):
#   paddock-<db>-<UTC>.dump[.age|.gpg]   the artifact
#   ...sha256                            `sha256sum -c` compatible checksum
#   ...meta                              key=value: time, versions, last migration
#
# The unencrypted dump is verified with `pg_restore --list` before it is
# encrypted, and never left on disk when encryption is on.
set -euo pipefail
umask 077

BACKUP_DIR=${BACKUP_DIR:-./backups}
BACKUP_RETENTION_DAYS=${BACKUP_RETENTION_DAYS:-14}
BACKUP_MIN_KEEP=${BACKUP_MIN_KEEP:-3}
BACKUP_ENCRYPT=${BACKUP_ENCRYPT:-none}
BACKUP_VIA=${BACKUP_VIA:-auto}
COMPOSE=${COMPOSE:-docker compose}
PGDB=${PGDB:-asm}
PGUSER_COMPOSE=${PGUSER_COMPOSE:-asm}

log() { printf '%s backup: %s\n' "$(date -u +%H:%M:%S)" "$*" >&2; }
die() { log "ERROR: $*"; exit 1; }

# asyncpg/SQLAlchemy-style DSNs -> libpq
pg_dsn() { local u=${1:-}; u=${u/postgresql+asyncpg:/postgresql:}; u=${u/postgres+asyncpg:/postgres:}; printf '%s' "$u"; }

if [[ $BACKUP_VIA == auto ]]; then
  if [[ -n ${DATABASE_URL:-} || -n ${PGHOST:-} ]]; then BACKUP_VIA=local; else BACKUP_VIA=compose; fi
fi

case $BACKUP_ENCRYPT in
  none) ;;
  age) command -v age >/dev/null || die "BACKUP_ENCRYPT=age but 'age' is not installed"
       [[ -n ${AGE_RECIPIENTS_FILE:-} || -n ${AGE_RECIPIENT:-} ]] || die "set AGE_RECIPIENTS_FILE or AGE_RECIPIENT" ;;
  gpg) command -v gpg >/dev/null || die "BACKUP_ENCRYPT=gpg but 'gpg' is not installed"
       [[ -n ${GPG_RECIPIENT:-} ]] || die "set GPG_RECIPIENT" ;;
  *) die "BACKUP_ENCRYPT must be none|age|gpg" ;;
esac

run_sql() {  # run a scalar query against the source DB
  if [[ $BACKUP_VIA == local ]]; then
    psql "$(pg_dsn "${DATABASE_URL:-}")" -XAtqc "$1"
  else
    $COMPOSE exec -T postgres psql -U "$PGUSER_COMPOSE" -d "$PGDB" -XAtqc "$1"
  fi
}

mkdir -p "$BACKUP_DIR"
chmod 700 "$BACKUP_DIR"
stamp=$(date -u +%Y%m%dT%H%M%SZ)
if [[ $BACKUP_VIA == local ]]; then
  dbname=$(run_sql "SELECT current_database()")
else
  dbname=$PGDB
fi
base="paddock-${dbname}-${stamp}"
tmp="$BACKUP_DIR/.${base}.dump.partial"
trap 'rm -f "$tmp" "$tmp.enc"' EXIT

log "dumping database '$dbname' via $BACKUP_VIA"
t0=$(date +%s)
if [[ $BACKUP_VIA == local ]]; then
  pg_dump --format=custom --compress=6 --no-password "$(pg_dsn "${DATABASE_URL:-}")" >"$tmp"
else
  $COMPOSE exec -T postgres pg_dump --format=custom --compress=6 -U "$PGUSER_COMPOSE" -d "$PGDB" >"$tmp"
fi
[[ -s $tmp ]] || die "pg_dump produced an empty file"

# Readability check BEFORE we trust (and maybe encrypt) it.
if command -v pg_restore >/dev/null; then
  pg_restore --list "$tmp" >/dev/null || die "pg_restore cannot read the dump"
elif [[ $BACKUP_VIA == compose ]]; then
  $COMPOSE exec -T postgres pg_restore --list <"$tmp" >/dev/null || die "pg_restore cannot read the dump"
fi

last_mig=$(run_sql "SELECT COALESCE(max(filename),'') FROM schema_migrations" 2>/dev/null || true)
mig_count=$(run_sql "SELECT count(*) FROM schema_migrations" 2>/dev/null || echo 0)
server_ver=$(run_sql "SHOW server_version" 2>/dev/null || echo unknown)
audit_rows=$(run_sql "SELECT count(*) FROM audit_log" 2>/dev/null || echo unknown)

final="$BACKUP_DIR/${base}.dump"
case $BACKUP_ENCRYPT in
  none) mv "$tmp" "$final" ;;
  age)
    final+=".age"
    args=()
    [[ -n ${AGE_RECIPIENTS_FILE:-} ]] && args+=(-R "$AGE_RECIPIENTS_FILE")
    [[ -n ${AGE_RECIPIENT:-} ]] && args+=(-r "$AGE_RECIPIENT")
    age "${args[@]}" -o "$tmp.enc" "$tmp"
    mv "$tmp.enc" "$final"; rm -f "$tmp" ;;
  gpg)
    final+=".gpg"
    gpg --batch --yes --trust-model always --encrypt --recipient "$GPG_RECIPIENT" \
        --output "$tmp.enc" "$tmp"
    mv "$tmp.enc" "$final"; rm -f "$tmp" ;;
esac

(cd "$BACKUP_DIR" && sha256sum "$(basename "$final")" >"$(basename "$final").sha256")
size=$(wc -c <"$final" | tr -d ' ')
cat >"$final.meta" <<EOF
created_at=$stamp
database=$dbname
source=$BACKUP_VIA
format=pg_dump-custom
encryption=$BACKUP_ENCRYPT
size_bytes=$size
server_version=$server_ver
pg_dump_version=$( (command -v pg_dump >/dev/null && pg_dump --version) || echo container)
last_migration=$last_mig
migrations_applied=$mig_count
audit_log_rows=$audit_rows
duration_sec=$(( $(date +%s) - t0 ))
EOF
log "wrote $final ($size bytes, sha256 $(cut -d' ' -f1 "$final.sha256" | cut -c1-16)...)"

# ---- retention ---------------------------------------------------------------
if [[ $BACKUP_RETENTION_DAYS -gt 0 ]]; then
  mapfile -t all < <(ls -1t "$BACKUP_DIR"/paddock-*.dump "$BACKUP_DIR"/paddock-*.dump.age \
                           "$BACKUP_DIR"/paddock-*.dump.gpg 2>/dev/null || true)
  cutoff=$(( $(date +%s) - BACKUP_RETENTION_DAYS * 86400 ))
  idx=0
  for f in "${all[@]}"; do
    idx=$((idx + 1))
    [[ $idx -le $BACKUP_MIN_KEEP ]] && continue
    mtime=$(stat -c %Y "$f" 2>/dev/null || stat -f %m "$f")
    if [[ $mtime -lt $cutoff ]]; then
      log "retention: removing $(basename "$f")"
      rm -f "$f" "$f.sha256" "$f.meta"
    fi
  done
fi
printf '%s\n' "$final"
