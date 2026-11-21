FROM python:3.11-slim

# subfinder (go) for better subdomain enumeration — optional; the worker falls
# back to a built-in wordlist + dnspython if the binary is missing.
RUN apt-get update \
 && apt-get install -y --no-install-recommends curl ca-certificates \
 && rm -rf /var/lib/apt/lists/*

# Install subfinder from a static release (ignore failures; module falls back).
RUN set -eu; \
    curl -fsSL -o /tmp/subfinder.zip \
        https://github.com/projectdiscovery/subfinder/releases/download/v2.6.6/subfinder_2.6.6_linux_amd64.zip \
    && apt-get update && apt-get install -y --no-install-recommends unzip \
    && unzip /tmp/subfinder.zip -d /usr/local/bin/ \
    && chmod +x /usr/local/bin/subfinder \
    && rm /tmp/subfinder.zip \
    && rm -rf /var/lib/apt/lists/* \
    || echo "subfinder install skipped; worker will fall back"

# Non-root runtime user.
RUN useradd --create-home --uid 10001 --shell /usr/sbin/nologin appuser

WORKDIR /app

COPY pyproject.toml ./
RUN pip install --no-cache-dir -e .

COPY app/ ./app/

# The passive worker only reads its code + does network I/O; give the user the
# app dir and a writable HOME for any dnspython / tooling caches.
RUN chown -R appuser:appuser /app /home/appuser

ENV PYTHONUNBUFFERED=1
ENV WORKER_ID=passive-1
ENV HOME=/home/appuser

USER appuser
CMD ["python", "-m", "app.main"]
