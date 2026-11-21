#!/usr/bin/env bash
# paddock — ops hardening self-audit.
# Invoked by `make harden-check`. Static checks always run; the audit-chain
# check runs only if the orchestrator is reachable. Exits non-zero if any
# hard check fails.
set -u

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
COMPOSE="$ROOT/docker-compose.yml"
OVERRIDE="$ROOT/docker-compose.override.yml"
GITIGNORE="$ROOT/.gitignore"
ENV_EXAMPLE="$ROOT/.env.example"
ORCH_URL="${ORCH_URL:-http://localhost:8080}"

pass=0; fail=0; warn=0
ok()   { printf "  \033[32mPASS\033[0m  %s\n" "$1"; pass=$((pass+1)); }
bad()  { printf "  \033[31mFAIL\033[0m  %s\n" "$1"; fail=$((fail+1)); }
note() { printf "  \033[33mWARN\033[0m  %s\n" "$1"; warn=$((warn+1)); }

echo "paddock hardening self-audit"
echo "================================="

# 1. AUTH_MODE defaults to enforce in the PROD compose (not the dev override).
if grep -Eq 'AUTH_MODE:[[:space:]]*\$\{AUTH_MODE:-enforce\}' "$COMPOSE"; then
  ok "orchestrator AUTH_MODE defaults to 'enforce' in docker-compose.yml"
else
  bad "orchestrator AUTH_MODE does not default to 'enforce' in docker-compose.yml"
fi
# ...and the legacy stub is deny-closed in prod.
if grep -Eq 'ALLOW_NO_AUTH:[[:space:]]*\$\{ALLOW_NO_AUTH:-false\}' "$COMPOSE"; then
  ok "legacy ALLOW_NO_AUTH is deny-closed (false) in docker-compose.yml"
else
  note "ALLOW_NO_AUTH default not pinned to false in docker-compose.yml"
fi

# 2. No plaintext secrets left in the prod compose (old literals must be gone).
if grep -Eq 'asm_dev|asm_dev_neo4j|neo4j/[A-Za-z0-9]' "$COMPOSE"; then
  bad "plaintext secret literal found in docker-compose.yml (expected \${...} substitution)"
  grep -nE 'asm_dev|asm_dev_neo4j|neo4j/[A-Za-z0-9]' "$COMPOSE" | sed 's/^/        /'
else
  ok "no plaintext DB/neo4j secret literals in docker-compose.yml"
fi
# Secrets must come from .env via ${...}.
if grep -Eq 'POSTGRES_PASSWORD:[[:space:]]*\$\{POSTGRES_PASSWORD\}' "$COMPOSE" \
   && grep -Eq 'NEO4J_AUTH:[[:space:]]*neo4j/\$\{NEO4J_PASSWORD\}' "$COMPOSE"; then
  ok "DB + neo4j passwords sourced from .env via \${...} substitution"
else
  bad "DB/neo4j passwords are not sourced from .env via \${...}"
fi

# 3. No known/default admin password shipped. ADMIN_BOOTSTRAP_PASSWORD must be
#    a ${...} reference in compose, never a literal; and no admin:admin anywhere.
if grep -Eq 'ADMIN_BOOTSTRAP_PASSWORD:[[:space:]]*\$\{ADMIN_BOOTSTRAP_PASSWORD' "$COMPOSE"; then
  ok "ADMIN_BOOTSTRAP_PASSWORD is a .env reference, not a literal"
else
  bad "ADMIN_BOOTSTRAP_PASSWORD is not a .env reference in docker-compose.yml"
fi
if grep -rIEq 'admin[:/=][[:space:]]*admin|ADMIN_BOOTSTRAP_PASSWORD[:=][[:space:]]*[A-Za-z0-9]' "$COMPOSE" "$OVERRIDE" 2>/dev/null; then
  bad "a hardcoded default admin credential appears to be shipped"
else
  ok "no hardcoded default admin credential shipped in compose files"
fi
# .env.example may carry only 'change-me' placeholders, never a real-looking secret.
if [ -f "$ENV_EXAMPLE" ]; then
  if grep -Eq '^(POSTGRES_PASSWORD|NEO4J_PASSWORD|ADMIN_BOOTSTRAP_PASSWORD)=change-me' "$ENV_EXAMPLE"; then
    ok ".env.example ships documented placeholders (change-me-*), not real secrets"
  else
    note ".env.example present but placeholders not in the expected 'change-me-*' form"
  fi
else
  bad ".env.example is missing"
fi

# 4. .env is gitignored and .env.example is allowed through.
if grep -Eq '^\.env(\b|$|\*)' "$GITIGNORE" && grep -Eq '^!\.env\.example' "$GITIGNORE"; then
  ok ".env is gitignored and .env.example is explicitly un-ignored"
else
  bad ".env is not gitignored (or .env.example not allowlisted) in .gitignore"
fi
# If this is a git checkout, make sure no real .env was committed.
if command -v git >/dev/null 2>&1 && git -C "$ROOT" rev-parse --is-inside-work-tree >/dev/null 2>&1; then
  if git -C "$ROOT" ls-files --error-unmatch .env >/dev/null 2>&1; then
    bad ".env is tracked by git — remove it from version control"
  else
    ok ".env is not tracked by git"
  fi
else
  note "not a git checkout here — skipped the tracked-.env check"
fi

# 5. Network posture: only orchestrator + dashboard publish ports in prod.
published=$(grep -nE '^\s*ports:' "$COMPOSE" | wc -l | tr -d ' ')
if [ "$published" = "2" ]; then
  ok "exactly 2 services publish host ports in docker-compose.yml (orchestrator + dashboard)"
else
  note "$published services publish host ports in docker-compose.yml (expected 2: orchestrator + dashboard)"
fi
if grep -Eq 'internal:[[:space:]]*true' "$COMPOSE"; then
  ok "an internal:true network is defined (workers/compute/data segmentation)"
else
  bad "no internal:true network found in docker-compose.yml"
fi

# 6. Audit-chain integrity — only if the stack is up.
echo
echo "audit-chain integrity (live, best-effort):"
if curl -fsS --max-time 3 "$ORCH_URL/healthz" >/dev/null 2>&1; then
  resp="$(curl -fsS --max-time 5 "$ORCH_URL/v1/audit/verify" 2>/dev/null)"
  rc=$?
  if [ $rc -ne 0 ] || [ -z "$resp" ]; then
    note "orchestrator is up but /v1/audit/verify did not respond (governance Stream A may not be deployed yet)"
  elif printf '%s' "$resp" | grep -Eq '"ok"[[:space:]]*:[[:space:]]*true'; then
    ok "audit chain verified: $resp"
  else
    bad "audit chain verification returned not-ok: $resp"
  fi
else
  note "orchestrator not reachable at $ORCH_URL — skipped /v1/audit/verify (bring the stack up to check)"
fi

echo
echo "================================="
printf "summary: \033[32m%d pass\033[0m, \033[31m%d fail\033[0m, \033[33m%d warn\033[0m\n" "$pass" "$fail" "$warn"
[ "$fail" -eq 0 ]
