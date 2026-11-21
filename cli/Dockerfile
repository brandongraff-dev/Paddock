# paddock CLI image. Build from the REPOSITORY ROOT (it vendors the sibling engines):
#
#   docker build -f cli/Dockerfile -t paddock .
#   docker run --rm -v "$PWD:/src" paddock scan                # scan the current directory
#   docker run --rm -v "$PWD:/src" --user "$(id -u):$(id -g)" paddock fix --yes
#
# Mount a volume on /cache to keep the OSV cache between runs:  -v paddock-cache:/cache

FROM python:3.12-slim AS build
WORKDIR /build
COPY sca/app sca/app
COPY codeanalysis/app codeanalysis/app
COPY remediation/app remediation/app
COPY orchestrator/app/__init__.py orchestrator/app/standards.py orchestrator/app/
COPY cli cli
RUN pip install --no-cache-dir build && python -m build --wheel --outdir /dist cli

FROM python:3.12-slim
# git is only needed for .gitignore-aware file listing and `paddock fix --pr`
RUN apt-get update \
    && apt-get install -y --no-install-recommends git \
    && rm -rf /var/lib/apt/lists/* \
    && git config --system --add safe.directory '*' \
    && useradd --create-home --uid 1000 paddock \
    && mkdir /cache /src && chown paddock /cache /src
COPY --from=build /dist/*.whl /tmp/
RUN pip install --no-cache-dir /tmp/*.whl && rm /tmp/*.whl
ENV PADDOCK_CACHE_DIR=/cache \
    PYTHONUNBUFFERED=1
USER paddock
WORKDIR /src
ENTRYPOINT ["paddock"]
CMD ["scan", "."]
