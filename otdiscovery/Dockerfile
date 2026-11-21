FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1

WORKDIR /srv/otdiscovery

# Install deps first to maximize layer reuse. otdiscovery only parses provided
# data + talks to the orchestrator/Postgres; it opens no socket to a device.
COPY pyproject.toml ./
RUN pip install --upgrade pip && \
    pip install aiohttp asyncpg

COPY app ./app

# Service port for healthz/readyz/ingest/analyze/stats
EXPOSE 8101

# Non-root user.
RUN useradd --system --home /srv/otdiscovery otdisc && chown -R otdisc:otdisc /srv/otdiscovery
USER otdisc

CMD ["python", "-m", "app.main"]
