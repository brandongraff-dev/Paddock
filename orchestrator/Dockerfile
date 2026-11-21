FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1

RUN groupadd --system app && useradd --system --gid app --home /app --shell /sbin/nologin app

# Pango/HarfBuzz for WeasyPrint (report PDFs). Fonts are embedded by the app.
RUN apt-get update \
 && apt-get install -y --no-install-recommends libpango-1.0-0 libpangoft2-1.0-0 libharfbuzz-subset0 \
 && rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY pyproject.toml ./
RUN pip install --no-cache-dir \
      "fastapi>=0.115" \
      "uvicorn[standard]>=0.30" \
      "asyncpg>=0.30" \
      "redis>=5" \
      "pydantic>=2" \
      "pydantic-settings>=2" \
      "python-json-logger>=2.0" \
      "PyJWT>=2.8" \
      "bcrypt>=4.0" \
      "jinja2>=3.1" \
      "weasyprint>=62"

COPY app ./app

RUN chown -R app:app /app
USER app

EXPOSE 8080

CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8080", "--no-access-log"]
