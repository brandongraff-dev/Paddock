# paddock fleet host agent.
#
# IMPORTANT: this image is NOT a docker-compose service for the platform. It is
# meant to run ON a target host, opt-in, to enroll + report a signed posture +
# apply HOST-LOCAL defensive blocks under the orchestrator's propose->approve->apply
# gate. To actually apply firewall rules it needs host networking and the
# NET_ADMIN capability; without them it still runs fine in dry-run / posture
# mode. A containerised agent cannot see host binaries, so those facts are
# reported as unavailable(containerised_agent) (UNKNOWN on the server, never a
# pass). See docs/FLEET_WIRING.md.
#
# The enrollment token is a secret: give it on STDIN (never as an argument, and
# prefer stdin to `-e`, which `docker inspect` shows). State (the Ed25519 key,
# the credential, the write-ahead counter) lives in the volume.
#
# Example (opt-in, on a target Linux host):
#   printf %s "$ENROLL_TOKEN" | docker run --rm -i \
#     --network host --cap-add NET_ADMIN \
#     -e PADDOCK_SERVER=https://orchestrator.internal:8080 \
#     -v paddock-agent-state:/var/lib/paddock-agent \
#     paddock/agent paddock enroll --token-stdin
#   docker run -d --restart on-failure --network host --cap-add NET_ADMIN \
#     -e PADDOCK_SERVER=https://orchestrator.internal:8080 \
#     -v paddock-agent-state:/var/lib/paddock-agent \
#     paddock/agent paddock run
#
# Standard library only: the image installs no Python dependencies (Ed25519 uses
# the vendored pure-Python signer unless `cryptography` is present).
FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    PADDOCK_DRY_RUN=true \
    PADDOCK_STATE_DIR=/var/lib/paddock-agent

WORKDIR /srv/agent

# iptables is needed only when applying real firewall rules on Linux; harmless
# otherwise. The agent degrades to dry-run when it cannot apply.
RUN apt-get update \
    && apt-get install -y --no-install-recommends iptables \
    && rm -rf /var/lib/apt/lists/* \
    && install -d -m 0700 /var/lib/paddock-agent

COPY pyproject.toml ./
COPY paddock_agent ./paddock_agent
RUN pip install --upgrade pip && pip install .

VOLUME ["/var/lib/paddock-agent"]

# Default to a read-only status so a bare `docker run` is inert and safe.
CMD ["paddock", "status"]
