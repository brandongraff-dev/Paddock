FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1

WORKDIR /srv/ontology

# Install deps first to maximize layer reuse.
COPY pyproject.toml ./
RUN pip install --upgrade pip && \
    pip install aiohttp asyncpg orjson

COPY app ./app

# Service port for healthz/readyz/project/stats
EXPOSE 8099

# Non-root user.
RUN useradd --system --home /srv/ontology ontology && chown -R ontology:ontology /srv/ontology
USER ontology

CMD ["python", "-m", "app.main"]
