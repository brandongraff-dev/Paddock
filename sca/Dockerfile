FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1

WORKDIR /srv/sca

# Install deps first to maximize layer reuse.
COPY pyproject.toml ./
RUN pip install --upgrade pip && \
    pip install aiohttp asyncpg redis orjson pyyaml

COPY app ./app

# Service port for healthz/readyz/scan/scan-dir/stats
EXPOSE 8094

# Non-root user.
RUN useradd --system --home /srv/sca sca && chown -R sca:sca /srv/sca
USER sca

CMD ["python", "-m", "app.main"]
