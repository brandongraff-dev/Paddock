FROM python:3.11-slim

ENV PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1

WORKDIR /srv

RUN apt-get update \
 && apt-get install -y --no-install-recommends curl \
 && rm -rf /var/lib/apt/lists/*

# Non-root runtime user.
RUN useradd --create-home --uid 10001 --shell /usr/sbin/nologin appuser

COPY pyproject.toml ./
RUN pip install --upgrade pip && pip install .

COPY app ./app

RUN chown -R appuser:appuser /srv /home/appuser

# Proving Ground is OFF unless an operator enables it AND provides a sandbox
# backend; the default "fake" backend builds nothing. Real runs need the docker
# backend, which requires a socket mounted by the operator (never baked in).
ENV HTTP_PORT=8103 \
    LOG_LEVEL=INFO \
    WARGAME_ENABLED=false \
    WARGAME_SANDBOX_BACKEND=fake

ENV HOME=/home/appuser

EXPOSE 8103

HEALTHCHECK --interval=15s --timeout=3s --start-period=10s --retries=5 \
  CMD curl -fsS http://localhost:8103/healthz || exit 1

USER appuser
CMD ["python", "-m", "uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8103"]
