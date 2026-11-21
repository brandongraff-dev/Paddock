FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1

RUN groupadd --system app && useradd --system --gid app --home /app --shell /sbin/nologin app

WORKDIR /app

# Install from pyproject.toml (single source of truth for dependencies; a
# hand-copied list here drifted and shipped images missing httpx/cryptography).
COPY pyproject.toml ./
COPY app ./app
RUN pip install --no-cache-dir ".[aws]"

RUN chown -R app:app /app
USER app

EXPOSE 8080

CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8080", "--no-access-log"]
