#!/bin/sh
# docker-entrypoint-initdb.d hook (runs after 100_app_role.sh on a fresh volume):
# give each compute service its own least-privilege, non-superuser,
# NOBYPASSRLS login role `paddock_svc_<name>` (created NOLOGIN by
# 029_service_tenancy.sql) a password + LOGIN, so the service connects as it and
# Postgres row-level security pins every statement to the tenant the service
# sets per transaction.
#
# Password per role, first match wins:
#   PADDOCK_SVC_<NAME>_DB_PASSWORD   (e.g. PADDOCK_SVC_INTEL_DB_PASSWORD)
#   PADDOCK_SERVICES_DB_PASSWORD
#   PADDOCK_APP_DB_PASSWORD
#   POSTGRES_PASSWORD
# With none set the roles stay NOLOGIN (the services then cannot connect).
#
# Safe whether the entrypoint executes or *sources* it (no `exit`, no `set -e`).
#
# Existing volumes: initdb hooks do not re-run. Apply once by hand:
#   docker compose exec postgres psql -U asm -d asm -f /docker-entrypoint-initdb.d/029_service_tenancy.sql
#   docker compose exec postgres sh /docker-entrypoint-initdb.d/101_service_roles.sh
# (and `SELECT paddock_apply_service_grants();` after any later migration that
# adds tables a service needs).
_paddock_services="intel correlation mlrisk triage ontology threatintel otdiscovery changewatch brain remediation sca codeanalysis graphsync wargame"
for _svc in $_paddock_services; do
  _up=$(printf '%s' "$_svc" | tr 'a-z' 'A-Z')
  eval "_pw=\${PADDOCK_SVC_${_up}_DB_PASSWORD:-}"
  [ -z "$_pw" ] && _pw="${PADDOCK_SERVICES_DB_PASSWORD:-${PADDOCK_APP_DB_PASSWORD:-${POSTGRES_PASSWORD:-}}}"
  if [ -z "$_pw" ]; then
    echo "101_service_roles.sh: no password for paddock_svc_${_svc}; stays NOLOGIN" >&2
  else
    psql -v ON_ERROR_STOP=1 -v pw="$_pw" \
      --username "${POSTGRES_USER:-postgres}" --dbname "${POSTGRES_DB:-postgres}" <<EOSQL
ALTER ROLE paddock_svc_${_svc} LOGIN PASSWORD :'pw';
EOSQL
    echo "101_service_roles.sh: paddock_svc_${_svc} can log in"
  fi
done
unset _paddock_services _svc _up _pw
