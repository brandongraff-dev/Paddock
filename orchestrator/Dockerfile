FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1

RUN groupadd --system app && useradd --system --gid app --home /app --shell /sbin/nologin app

# Pango/HarfBuzz for WeasyPrint (report PDFs). Fonts are embedded by the app.
RUN apt-get update \
 && apt-get install -y --no-install-recommends libpango-1.0-0 libpangoft2-1.0-0 libharfbuzz-subset0 \
 && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Install from pyproject.toml (single source of truth for dependencies; a
# hand-copied list here drifted and shipped images missing httpx/cryptography).
# Built from the REPOSITORY ROOT (context: ., file: orchestrator/Dockerfile)
# so the migrations ship inside the image: the app migrates on startup
# (migrate_on_startup) and app.migrate looks in /app/schema first.
# Provable containment: the pure evaluator library ships inside the image (the evaluator runs
# in the orchestrator process; see docs/ASSURANCE_P1.md D1/D2). Installed before the app so the
# lazy `import paddock_assurance` always resolves.
COPY assurance/pyproject.toml assurance/README.md /tmp/assurance/
COPY assurance/paddock_assurance /tmp/assurance/paddock_assurance
RUN pip install --no-cache-dir /tmp/assurance && rm -rf /tmp/assurance

COPY orchestrator/pyproject.toml ./
COPY orchestrator/app ./app
COPY schema ./schema
RUN pip install --no-cache-dir ".[aws]"

RUN chown -R app:app /app
USER app

EXPOSE 8080

CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8080", "--no-access-log"]
