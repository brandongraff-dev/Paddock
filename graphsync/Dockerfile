FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1

WORKDIR /srv/graphsync

# Install deps first to maximize layer reuse.
COPY pyproject.toml ./
RUN pip install --upgrade pip && \
    pip install "neo4j>=5.14" "asyncpg>=0.29" "aiohttp>=3.9" "uvloop>=0.19"

COPY app ./app

# Service port for healthz/readyz/paths/blast/neighborhood/resync/stats
EXPOSE 8096

# Non-root user.
RUN useradd --system --home /srv/graphsync graphsync && \
    chown -R graphsync:graphsync /srv/graphsync
USER graphsync

CMD ["python", "-m", "app.main"]
