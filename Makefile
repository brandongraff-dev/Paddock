# paddock — operator targets
.DEFAULT_GOAL := help

COMPOSE ?= docker compose
ORCH_URL ?= http://localhost:8080

# ---------- lifecycle ----------

.PHONY: quickstart
quickstart: ## one command: env + build/up + seed demo graph (first-time setup)
	@test -f .env || (cp .env.example .env && echo "==> created .env from .env.example (dev defaults are fine)")
	$(COMPOSE) up -d --build
	@$(MAKE) --no-print-directory demo

.PHONY: up
up: ## bring the full stack up (DEV profile: open ports + AUTH_MODE=dev)
	$(COMPOSE) up -d --build

.PHONY: demo
demo: ## seed a demo graph + print the dashboard URL and default login
	python3 scripts/seed_demo.py
	@echo ""
	@echo "  ┌─────────────────────────────────────────────────────────────┐"
	@echo "  │  paddock is ready                                        │"
	@echo "  ├─────────────────────────────────────────────────────────────┤"
	@echo "  │  Dashboard      http://localhost:3000                         │"
	@echo "  │  API docs       http://localhost:8080/docs                    │"
	@echo "  │                                                               │"
	@echo "  │  Login          DEV profile (make up) runs AUTH_MODE=dev:      │"
	@echo "  │                 no login required — you are a synthetic admin. │"
	@echo "  │                 Hardened profile seeds user 'admin' with the   │"
	@echo "  │                 password from ADMIN_BOOTSTRAP_PASSWORD (.env).  │"
	@echo "  └─────────────────────────────────────────────────────────────┘"

.PHONY: down
down: ## stop the stack (keeps volumes)
	$(COMPOSE) down

.PHONY: nuke
nuke: ## stop + delete volumes (DESTROYS all data)
	@echo "This will delete postgres volume. Press Ctrl-C now to abort."
	@sleep 3
	$(COMPOSE) down -v

.PHONY: logs
logs: ## tail every service's logs
	$(COMPOSE) logs -f --tail=200

.PHONY: logs-%
logs-%: ## tail one service's logs (e.g. make logs-orchestrator)
	$(COMPOSE) logs -f --tail=500 $*

.PHONY: ps
ps: ## list containers
	$(COMPOSE) ps

.PHONY: status
status: ## hit /healthz on every service
	@echo "orchestrator:" && curl -fsS $(ORCH_URL)/healthz || echo "  down"
	@echo "intel:"        && curl -fsS http://localhost:8090/healthz || echo "  down"
	@echo "correlation:"  && curl -fsS http://localhost:8091/healthz || echo "  down"
	@echo "dashboard:"    && curl -fsS -I http://localhost:3000 | head -1 || echo "  down"

# ---------- lite (single node) ----------
# postgres + redis + orchestrator + dashboard + worker-passive, hardened
# (AUTH_MODE=enforce, REQUIRE_SCOPE_PROOF=true). No neo4j/graphsync/ML/LLM.

LITE ?= $(COMPOSE) -f docker-compose.lite.yml

.PHONY: lite-env
lite-env:
	@test -f .env || (cp .env.example .env && echo "==> created .env from .env.example")
	@grep -Eq '^SERVICE_API_KEY=.+' .env || ( \
	  echo "SERVICE_API_KEY=$$(python3 -c 'import secrets;print(secrets.token_urlsafe(32))')" >> .env && \
	  echo "==> generated SERVICE_API_KEY in .env (worker -> orchestrator credential)")

.PHONY: lite
lite: lite-env ## single-node LITE stack (~1 GB RAM): sign in as admin, the /setup wizard takes it from there
	$(LITE) up -d --build
	@echo ""
	@echo "  Paddock lite is starting:  http://localhost:3000"
	@echo "  Sign in as 'admin' with ADMIN_BOOTSTRAP_PASSWORD from .env;"
	@echo "  the first-run wizard (/setup) walks you through domain -> proof -> first scan."
	@echo "  make lite-demo seeds demo data · make lite-status · make lite-down"

.PHONY: lite-active
lite-active: lite-env ## lite + the active worker (polite HTTP/TLS/port probing)
	$(LITE) --profile active up -d --build

.PHONY: lite-demo
lite-demo: ## seed the demo graph into the lite stack (uses SERVICE_API_KEY from .env)
	@SERVICE_API_KEY="$$(grep -E '^SERVICE_API_KEY=' .env | tail -1 | cut -d= -f2-)" python3 scripts/seed_demo.py

.PHONY: lite-status
lite-status: ## health of the lite stack
	@$(LITE) ps
	@curl -fsS $(ORCH_URL)/healthz && echo "  <- orchestrator" || echo "orchestrator: down"
	@curl -fsS -o /dev/null -w "%{http_code}  <- dashboard\n" http://localhost:3000/ || echo "dashboard: down"

.PHONY: lite-down
lite-down: ## stop the lite stack (keeps data)
	$(LITE) --profile active down

# ---------- scope ----------

.PHONY: seed-scope
seed-scope: ## load the safe example scope (localhost + scanme.nmap.org)
	python3 scripts/seed_scope.py

.PHONY: seed-demo
seed-demo: ## seed a representative demo graph (acme-demo.example) so the UI isn't empty
	python3 scripts/seed_demo.py

.PHONY: scope-list
scope-list:
	@curl -fsS $(ORCH_URL)/v1/scope | python3 -m json.tool

.PHONY: scope-add
scope-add: ## add a scope entry: make scope-add KIND=domain VALUE=example.com AUTH="doc ref"
	@test -n "$(KIND)"  || (echo "KIND required (domain|subdomain_wildcard|ipv4_cidr|ipv6_cidr|asn)" && exit 1)
	@test -n "$(VALUE)" || (echo "VALUE required" && exit 1)
	@curl -fsS -X POST $(ORCH_URL)/v1/scope \
	  -H 'content-type: application/json' \
	  -d "$$(python3 -c 'import json,os; print(json.dumps({"kind":os.environ["KIND"],"value":os.environ["VALUE"],"added_by":"makefile","auth_doc_ref":os.environ.get("AUTH","")}))')" \
	  | python3 -m json.tool

# ---------- scans ----------

.PHONY: scan
scan: ## queue a scan: make scan KIND=full_recon TARGET=example.com
	@test -n "$(KIND)"   || (echo "KIND required" && exit 1)
	@test -n "$(TARGET)" || (echo "TARGET required" && exit 1)
	@curl -fsS -X POST $(ORCH_URL)/v1/scans \
	  -H 'content-type: application/json' \
	  -d "$$(python3 -c 'import json,os; print(json.dumps({"kind":os.environ["KIND"],"target":os.environ["TARGET"]}))')" \
	  | python3 -m json.tool

.PHONY: scans-list
scans-list:
	@curl -fsS $(ORCH_URL)/v1/scans?limit=20 | python3 -m json.tool

# ---------- tests ----------

.PHONY: test
test: test-orchestrator test-passive test-active test-intel test-correlation test-dashboard

.PHONY: test-orchestrator
test-orchestrator:
	cd orchestrator && python -m pytest -q

.PHONY: test-passive
test-passive:
	cd workers/passive && python -m pytest -q

.PHONY: test-active
test-active:
	cd workers/active && python -m pytest -q

.PHONY: test-intel
test-intel:
	cd intel && python -m pytest -q

.PHONY: test-correlation
test-correlation:
	cd correlation && python -m pytest -q

.PHONY: test-dashboard
test-dashboard:
	cd dashboard && npm run test

# ---------- hardening ----------

.PHONY: harden-check
harden-check: ## ops self-audit: AUTH_MODE=enforce, no plaintext secrets, .env gitignored, no default creds, audit chain
	@ORCH_URL=$(ORCH_URL) bash hardening/harden_check.sh

.PHONY: integration
integration: ## end-to-end pipeline harness (drives all services, asserts cross-service contracts; demo DB only)
	python3 hardening/integration_test.py

.PHONY: realrun
realrun: ## authorized real-target run + crude FP measurement (default scanme.nmap.org)
	python3 hardening/realrun.py $(TARGET)

# ---------- housekeeping ----------

.PHONY: fmt
fmt:
	ruff format orchestrator workers intel correlation
	cd dashboard && npm run format

.PHONY: lint
lint:
	ruff check orchestrator workers intel correlation
	cd dashboard && npm run lint

.PHONY: help
help:
	@awk 'BEGIN {FS = ":.*?## "} /^[a-zA-Z0-9%_.-]+:.*?## / {printf "  \033[36m%-22s\033[0m %s\n", $$1, $$2}' $(MAKEFILE_LIST)
