#!/usr/bin/env bash
# One-command bootstrap: build everything, bring it up, seed safe scope, print URLs.
set -euo pipefail

cd "$(dirname "$0")/.."

echo "==> building images"
docker compose build

echo "==> starting stack"
docker compose up -d

echo "==> waiting for orchestrator"
for i in {1..90}; do
  if curl -fsS http://localhost:8080/healthz >/dev/null 2>&1; then
    echo "   orchestrator up"
    break
  fi
  sleep 1
done

echo "==> seeding safe default scope"
python3 scripts/seed_scope.py

echo
echo "==> ready"
echo "    dashboard:    http://localhost:3000"
echo "    orchestrator: http://localhost:8080/docs"
echo "    intel stats:  http://localhost:8090/stats"
echo "    corr rules:   http://localhost:8091/rules"
echo
echo "Add your own authorized scope via the dashboard or:"
echo "    make scope-add KIND=subdomain_wildcard VALUE=yours.example AUTH='your note'"
echo "Then kick off a scan:"
echo "    make scan KIND=full_recon TARGET=yours.example"
