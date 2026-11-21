FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1

WORKDIR /srv/mlrisk

# Install deps first to maximize layer reuse. numpy + scikit-learn are the ML
# core; asyncpg/aiohttp for DB + HTTP. scikit-learn is imported defensively so
# the service degrades to the heuristic prior / z-score fallback if it is gone.
COPY pyproject.toml ./
RUN pip install --upgrade pip && \
    pip install numpy scikit-learn asyncpg aiohttp orjson

COPY app ./app

# Service port for healthz/readyz/stats/retrain/score/detect-anomalies.
EXPOSE 8098

# Non-root user.
RUN useradd --system --home /srv/mlrisk mlrisk && chown -R mlrisk:mlrisk /srv/mlrisk
USER mlrisk

CMD ["python", "-m", "app.main"]
