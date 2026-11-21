FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1

WORKDIR /srv/codeanalysis

# Core deps first to maximize layer reuse. Semgrep is OPTIONAL: install it by
# building with --build-arg WITH_SEMGREP=1 (the service degrades to a bundled
# taint scanner when the binary is absent).
COPY pyproject.toml ./
RUN pip install --upgrade pip && \
    pip install aiohttp asyncpg uvloop

ARG WITH_SEMGREP=0
RUN if [ "$WITH_SEMGREP" = "1" ]; then pip install semgrep; fi

COPY app ./app

# Service port for healthz/readyz/analyze/reachability/stats
EXPOSE 8097

# Non-root user.
RUN useradd --system --home /srv/codeanalysis codeanalysis && \
    chown -R codeanalysis:codeanalysis /srv/codeanalysis
USER codeanalysis

CMD ["python", "-m", "app.main"]
