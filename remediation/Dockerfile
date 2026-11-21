FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1

WORKDIR /srv/remediation

# Install deps first to maximize layer reuse. The anthropic SDK is OPTIONAL and
# deliberately NOT installed here: the deterministic generators + gate + the
# rule-based verifier work fully without it. `gh` is only needed when
# REMEDIATION_OPEN_PR=true (off by default); install it in that profile.
COPY pyproject.toml ./
RUN pip install --upgrade pip && \
    pip install aiohttp asyncpg

COPY app ./app

# Service port for healthz/readyz/stats/propose
EXPOSE 8102

# Non-root user.
RUN useradd --system --home /srv/remediation remediation && \
    chown -R remediation:remediation /srv/remediation
USER remediation

CMD ["python", "-m", "app.main"]
