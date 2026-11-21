FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1

WORKDIR /srv/changewatch

# Install deps first to maximize layer reuse.
COPY pyproject.toml ./
RUN pip install --upgrade pip && \
    pip install aiohttp asyncpg redis orjson

COPY app ./app

# Service port for healthz/readyz/stats/run
EXPOSE 8092

# Non-root user.
RUN useradd --system --home /srv/changewatch changewatch && \
    chown -R changewatch:changewatch /srv/changewatch
USER changewatch

CMD ["python", "-m", "app.main"]
