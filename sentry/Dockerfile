# Paddock Sentry -- passive sensor image (~60 MB). Runs on amd64 and arm64
# (Raspberry Pi 4/5, mini-PCs, router app platforms).
#
#   docker run -d --name paddock-sentry --restart unless-stopped \
#     --network host --cap-drop ALL --cap-add NET_RAW --cap-add NET_ADMIN \
#     --read-only --tmpfs /tmp -v paddock-sentry:/var/lib/paddock-sentry \
#     -e PADDOCK_SERVER=https://paddock.example:8101 -e PADDOCK_SENTRY_TOKEN=... \
#     ghcr.io/<org>/paddock-sentry run --iface eth1
FROM python:3.12-slim
RUN apt-get update && apt-get install -y --no-install-recommends tcpdump \
    && rm -rf /var/lib/apt/lists/*
WORKDIR /opt/sentry
COPY pyproject.toml ./
COPY paddock_sentry ./paddock_sentry
RUN pip install --no-cache-dir . && mkdir -p /var/lib/paddock-sentry/outbox
VOLUME /var/lib/paddock-sentry
ENTRYPOINT ["paddock-sentry"]
CMD ["doctor"]
