# paddock fleet host agent.
#
# IMPORTANT: this image is NOT a docker-compose service for the platform. It is
# meant to run ON a target host, opt-in, to enroll + report inventory + apply
# HOST-LOCAL defensive blocks under the orchestrator's propose->approve->apply
# gate. To actually apply firewall rules it needs host networking and the
# NET_ADMIN capability; without them it still runs fine in dry-run / inventory
# mode. See docs/FLEET_WIRING.md.
#
# Example (opt-in, on a target Linux host):
#   docker run --rm \
#     --network host --cap-add NET_ADMIN \
#     -e PADDOCK_SERVER=https://orchestrator.internal:8080 \
#     -e PADDOCK_DRY_RUN=true \
#     -v paddock-agent-cred:/root/.config/paddock-agent \
#     -v paddock-quarantine:/var/lib/paddock-agent/quarantine \
#     paddock/agent paddock enroll --token "$FLEET_ENROLL_TOKEN"
#
FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    PADDOCK_DRY_RUN=true

WORKDIR /srv/agent

# iptables is needed only when applying real firewall rules on Linux; harmless
# otherwise. The agent degrades to dry-run when it cannot apply.
RUN apt-get update \
    && apt-get install -y --no-install-recommends iptables \
    && rm -rf /var/lib/apt/lists/*

COPY pyproject.toml ./
COPY paddock_agent ./paddock_agent
RUN pip install --upgrade pip && pip install .

# Default to dry-run status so a bare `docker run` is inert and safe.
CMD ["paddock", "status"]
