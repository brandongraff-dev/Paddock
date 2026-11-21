.PHONY: test run build fmt clean

PYTHON ?= python3
PG_BIN ?= /usr/lib/postgresql/16/bin

test:
	# Postgres refuses to run as root, so if we are root we drop to the
	# postgres user. pytest-postgresql spawns real initdb/pg_ctl under us.
	@if [ "$$(id -u)" = "0" ]; then \
	  chown -R postgres:postgres $(CURDIR) 2>/dev/null || true; \
	  su postgres -s /bin/bash -c "cd $(CURDIR) && PATH=$(PG_BIN):\$$PATH $(PYTHON) -m pytest tests/ -v -p no:cacheprovider"; \
	else \
	  PATH=$(PG_BIN):$$PATH $(PYTHON) -m pytest tests/ -v -p no:cacheprovider; \
	fi

run:
	$(PYTHON) -m uvicorn app.main:app --host 0.0.0.0 --port 8080 --reload

build:
	docker build -t paddock/orchestrator .

clean:
	rm -rf .pytest_cache __pycache__ app/__pycache__ app/routers/__pycache__ tests/__pycache__
