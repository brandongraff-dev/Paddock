FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1

WORKDIR /srv/threatintel

# Install deps first to maximize layer reuse. stix2 / taxii2-client are
# OPTIONAL: the service parses STIX/TAXII with a hand parser when they are
# absent. They are installed here as a convenience but the image boots and
# functions without them.
COPY pyproject.toml ./
RUN pip install --upgrade pip && \
    pip install aiohttp asyncpg redis orjson && \
    pip install stix2 taxii2-client || true

COPY app ./app

# Service port for healthz/readyz/ingest/feeds/poll/match/stats
EXPOSE 8100

# Non-root user.
RUN useradd --system --home /srv/threatintel threatintel && \
    chown -R threatintel:threatintel /srv/threatintel
USER threatintel

CMD ["python", "-m", "app.main"]
