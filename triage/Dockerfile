FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1

WORKDIR /srv/triage

# Install deps first to maximize layer reuse.
COPY pyproject.toml ./
RUN pip install --upgrade pip && \
    pip install aiohttp asyncpg redis orjson

COPY app ./app

# Service port for healthz/readyz/stats/run/resolve-owners
EXPOSE 8093

# Non-root user.
RUN useradd --system --home /srv/triage triage && \
    chown -R triage:triage /srv/triage
USER triage

CMD ["python", "-m", "app.main"]
