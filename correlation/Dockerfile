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

# Service only reads its bundled rules (/srv/app/rules) and binds a high port
# (8091, unprivileged); give the user the app tree + a writable HOME.
RUN chown -R appuser:appuser /srv /home/appuser

# Rules bundled in the image; the mounted /policies directory overlays them.
ENV BUILTIN_RULES_DIR=/srv/app/rules \
    POLICIES_DIR=/policies \
    HTTP_PORT=8091 \
    SWEEP_INTERVAL_MIN=15 \
    LOG_LEVEL=INFO

ENV HOME=/home/appuser

EXPOSE 8091

HEALTHCHECK --interval=15s --timeout=3s --start-period=10s --retries=5 \
  CMD curl -fsS http://localhost:8091/healthz || exit 1

USER appuser
CMD ["python", "-m", "uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8091"]
