# paddock active worker
# Polite, loud, transparent.
FROM python:3.12-slim AS base

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1 \
    USER_AGENT="paddock-scanner/1.0 (+defensive-scanner)" \
    DATA_DIR=/data \
    PD_VERSION_NAABU=2.3.1 \
    PD_VERSION_NUCLEI=3.3.0 \
    PD_VERSION_TLSX=1.1.6 \
    PD_VERSION_KATANA=1.1.0

# OS deps + runtime libs that chromium needs.
RUN apt-get update && apt-get install -y --no-install-recommends \
      ca-certificates curl unzip git libpcap0.8 tini \
      # chromium runtime libs (playwright installs browser binary, but needs these)
      libglib2.0-0 libnss3 libnspr4 libatk1.0-0 libatk-bridge2.0-0 \
      libcups2 libdrm2 libxkbcommon0 libxcomposite1 libxdamage1 \
      libxfixes3 libxrandr2 libgbm1 libasound2 libpango-1.0-0 \
      libpangocairo-1.0-0 libcairo2 libatspi2.0-0 \
    && rm -rf /var/lib/apt/lists/*

# ProjectDiscovery tools: naabu, nuclei, tlsx, katana.
# Downloaded as release zips and dropped into /usr/local/bin. If a release
# URL is unreachable at build time the install script continues and the
# module falls back to a "tool unavailable" finding at runtime.
RUN set -eu; \
    ARCH=$(dpkg --print-architecture); \
    case "$ARCH" in \
      amd64)  PD_ARCH=amd64 ;; \
      arm64)  PD_ARCH=arm64 ;; \
      *)      PD_ARCH=amd64 ;; \
    esac; \
    install_pd() { \
      name="$1"; ver="$2"; \
      url="https://github.com/projectdiscovery/${name}/releases/download/v${ver}/${name}_${ver}_linux_${PD_ARCH}.zip"; \
      echo "fetching $url"; \
      if curl -fsSL "$url" -o "/tmp/${name}.zip"; then \
        unzip -o "/tmp/${name}.zip" -d "/tmp/${name}-extract" > /dev/null; \
        find "/tmp/${name}-extract" -maxdepth 2 -type f -name "$name" -exec install -m 0755 {} "/usr/local/bin/${name}" \; ; \
        rm -rf "/tmp/${name}.zip" "/tmp/${name}-extract"; \
      else \
        echo "WARNING: failed to install ${name}; runtime will emit a tool-unavailable finding"; \
      fi; \
    }; \
    install_pd naabu   "${PD_VERSION_NAABU}"; \
    install_pd nuclei  "${PD_VERSION_NUCLEI}"; \
    install_pd tlsx    "${PD_VERSION_TLSX}"; \
    install_pd katana  "${PD_VERSION_KATANA}"

# Non-root runtime user. Created before the Playwright install so the browser
# bundle can be placed somewhere the user can read/execute.
RUN useradd --create-home --uid 10001 --shell /usr/sbin/nologin appuser

WORKDIR /app

# Install Playwright browsers to a shared, world-readable location (not
# /root/.cache) so the non-root user can launch chromium at runtime.
ENV PLAYWRIGHT_BROWSERS_PATH=/ms-playwright

# Python deps
COPY pyproject.toml /app/
RUN pip install --upgrade pip setuptools wheel \
 && pip install -e . \
 && mkdir -p /ms-playwright \
 && python -m playwright install --with-deps chromium || true \
 && chmod -R a+rX /ms-playwright 2>/dev/null || true

COPY app /app/app

# Dirs the worker writes at runtime: screenshots + the user's HOME (chromium
# profile / caches). ProjectDiscovery binaries live in /usr/local/bin (0755,
# world-executable) so no extra grant is needed for them.
RUN mkdir -p /data/screenshots \
 && chown -R appuser:appuser /app /data /ms-playwright /home/appuser

ENV PYTHONPATH=/app \
    HOME=/home/appuser

USER appuser
ENTRYPOINT ["/usr/bin/tini", "--"]
CMD ["python", "-m", "app.main"]
