# Getting started

**Requirements:** Docker + Docker Compose.

```bash
git clone https://github.com/brandongraff-dev/paddock
cd paddock

make quickstart        # = cp .env.example .env + docker compose up -d --build + make demo
```

`make demo` seeds a representative demo surface (the fictional
`acme-demo.example`), so the dashboard shows a graph, findings and an attack
chain right away.

| | URL |
|---|---|
| Dashboard | <http://localhost:3000> — start on the **Graph** page |
| API docs (interactive) | <http://localhost:8080/docs> |

The dev profile runs `AUTH_MODE=dev` (you are a synthetic admin, no login).
The hardened profile (`docker compose -f docker-compose.yml up -d`) enforces
auth and seeds an `admin` user whose password comes from
`ADMIN_BOOTSTRAP_PASSWORD` in `.env`.

## Point it at your own surface

1. **Add scope** — only assets you are authorized to assess:

    ```bash
    pip install ./sdk/python
    paddockctl login --url http://localhost:8080 --api-key <admin key>
    paddockctl scope add domain example.com --auth-doc-ref "SOW-2026-14"
    ```

2. **Run a scan** — `paddockctl scan run full_recon example.com --wait`.
3. **Review findings** — in the dashboard, or
   `paddockctl findings list --severity critical`.
4. **Wire it into your tools** — see the [API](API.md) and
   [SDKs, CLI & Terraform](SDK.md).

## Stop / reset

```bash
make down      # stop (keeps data)
make nuke      # stop + wipe volumes
make status    # health-check every service
```
