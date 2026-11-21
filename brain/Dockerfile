FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1

WORKDIR /srv/brain

# Install deps first to maximize layer reuse. The anthropic SDK is OPTIONAL:
# install it so the LLM path is available when a key is present, but the
# service runs fine (template triage + fallback NL-query) without it.
COPY pyproject.toml ./
RUN pip install --upgrade pip && \
    pip install aiohttp asyncpg sqlglot && \
    pip install anthropic || echo "anthropic optional; continuing without it"

COPY app ./app

# Service port for healthz/readyz/stats/triage/ask
EXPOSE 8095

# Non-root user.
RUN useradd --system --home /srv/brain brain && chown -R brain:brain /srv/brain
USER brain

CMD ["python", "-m", "app.main"]
