#!/bin/sh
# docker-entrypoint-initdb.d hook (runs after 099_tenancy.sql on a fresh volume):
# give the non-superuser application role `paddock_app` a password + LOGIN so the
# orchestrator can connect as it (RLS is bypassed for the superuser).
#
# Written to be safe whether the entrypoint executes or *sources* it (no `exit`,
# no `set -e`).
#
# Existing volumes: initdb hooks do not re-run. Apply once by hand:
#   docker compose exec postgres psql -U asm -d asm -f /docker-entrypoint-initdb.d/098_audit_keyed.sql
#   docker compose exec postgres psql -U asm -d asm -f /docker-entrypoint-initdb.d/099_tenancy.sql
#   docker compose exec postgres sh /docker-entrypoint-initdb.d/100_app_role.sh
_paddock_pw="${PADDOCK_APP_DB_PASSWORD:-${POSTGRES_PASSWORD:-}}"
if [ -z "$_paddock_pw" ]; then
  echo "100_app_role.sh: no PADDOCK_APP_DB_PASSWORD; paddock_app stays NOLOGIN" >&2
else
  psql -v ON_ERROR_STOP=1 -v pw="$_paddock_pw" \
    --username "${POSTGRES_USER:-postgres}" --dbname "${POSTGRES_DB:-postgres}" <<'EOSQL'
ALTER ROLE paddock_app LOGIN PASSWORD :'pw';
EOSQL
  echo "100_app_role.sh: paddock_app can log in"
fi
unset _paddock_pw
