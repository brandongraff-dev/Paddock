FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1

WORKDIR /srv/intel

# Install deps first to maximize layer reuse.
COPY pyproject.toml ./
RUN pip install --upgrade pip && \
    pip install aiohttp asyncpg redis orjson

COPY app ./app

# Service port for healthz/readyz/sync/stats
EXPOSE 8090

# Non-root user.
RUN useradd --system --home /srv/intel intel && chown -R intel:intel /srv/intel
USER intel

CMD ["python", "-m", "app.main"]
