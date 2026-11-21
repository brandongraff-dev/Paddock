# Running a status page

Paddock exposes a deliberately boring, public health feed that you can point a
status page, an uptime monitor or a customer's probe at.

## `GET /status`

No authentication, no tenant data, no internal detail:

```json
{
  "status": "operational",
  "components": [
    {"name": "api", "status": "up"},
    {"name": "database", "status": "up"},
    {"name": "queue", "status": "up"},
    {"name": "scheduler", "status": "up"}
  ],
  "updated_at": "2027-01-10T09:30:00+00:00"
}
```

* `status` is `operational`, or `degraded` if any component is not `up`.
* Components are a fixed set: `api` (this process answered), `database`, `queue`
  (Redis) and `scheduler` (the background loop; only when it is enabled). A component
  is `up` or `degraded`. The reason, hostnames, versions and counts are never included.
* The answer is **cached in-process for 15 seconds** (`STATUS_CACHE_SEC`) and served with
  `Cache-Control: public, max-age=15`, and probes have a 2 s timeout, so public traffic
  (or abuse) cannot become database load. It always answers HTTP `200` while the API is
  up so monitors can read the body; alert on `status != "operational"`.
* Internal liveness/readiness stay on `/healthz` and `/readyz` (unchanged, for orchestrators).

Put it behind your CDN/WAF as you would any public route; it is safe to cache at the edge.

## Publishing a page

Any of these work; none needs a Paddock change.

1. **Hosted status service** (Better Stack, Statuspage, Instatus, Uptime Kuma, …): add an
   HTTP monitor on `https://<api-host>/status`, assert `200` and JSON `status == "operational"`
   (or the keyword `operational`), check every 30–60 s, require 2–3 consecutive failures before
   flagging an incident. Map the components to the monitor's component list if it supports it.
2. **Static page you host yourself:** a small page that fetches `/status` client-side
   (CORS: add the page's origin to `CORS_ORIGINS`) and renders the components; keep the
   *history* and incident posts in the status tool, not in Paddock.
3. **Synthetic checks per region:** probe from outside your own network, not from the
   cluster, or you will report "operational" during a network partition.

## What to publish, what not to

* Do publish: component state, incident start/identified/resolved times, planned maintenance.
* Do not publish: tenant names, internal hostnames, stack traces, the content of `/readyz`
  (it contains error strings), or raw metrics. `/metrics` is token-protected and stays that way.
* Run the status page on infrastructure that does **not** share fate with the product
  (different provider/DNS), otherwise it goes down with the incident it is meant to report.

## Operating notes

* A `scheduler: degraded` means the background loop has exited; scheduled scans, digests and
  usage reporting to Stripe stop until the orchestrator restarts. The API itself is unaffected.
* `database: degraded` / `queue: degraded` for longer than one probe interval usually means the
  dependency is unreachable from the orchestrator; check `/readyz` from inside the network.
* To tune the cache lifetime set `STATUS_CACHE_SEC` (seconds, process start).
