# RUNBOOK — running palantir-asm against a real authorized target

This is the end-to-end procedure for running the full stack against an
**authorized** target and measuring a crude false-positive rate. It assumes a
fresh checkout and Docker + Docker Compose.

---

## 0. Authorized use — read this first

> You may only point this platform at assets you **own** or are **explicitly,
> documentedly authorized** to test. The safe default scope is
> `scanme.nmap.org` (Nmap's official legal scan target —
> <https://nmap.org/book/legal-issues.html>) and loopback (`127.0.0.0/8`).
> Everything else must be added to the scope allowlist **with an authorization
> note** that points at the document granting you permission. Scanning a host
> you are not authorized to test is very likely illegal. This tool performs
> **detection, not exploitation**: no payloads, no credential testing, no
> evasion. The scope allowlist is enforced at two layers and every outbound
> request is audited.

---

## 1. Configure secrets

```bash
cp .env.example .env
# edit .env and set strong values:
#   POSTGRES_PASSWORD, NEO4J_PASSWORD, ADMIN_BOOTSTRAP_PASSWORD
#   ANTHROPIC_API_KEY (optional; brain degrades gracefully without it)
# generate values with e.g.:  openssl rand -base64 24
```

`.env` is gitignored. Never commit it.

## 2. Bring the stack up

**Dev profile** (open ports for debugging, `AUTH_MODE=dev` synthetic admin —
`docker compose` auto-merges `docker-compose.override.yml`):

```bash
make up            # == docker compose up -d --build
```

**Hardened/prod profile** (only orchestrator + dashboard published,
`AUTH_MODE=enforce`, workers/compute/data on the internal network):

```bash
docker compose -f docker-compose.yml up -d --build
```

Check health:

```bash
make ps
make status
```

## 3. Log in (hardened profile)

Under `AUTH_MODE=enforce` the orchestrator requires authentication. On first
boot it sets the `admin` password from `ADMIN_BOOTSTRAP_PASSWORD` (or generates
one and logs it **once** — grep the orchestrator logs):

```bash
make logs-orchestrator | grep -i bootstrap   # if you let it auto-generate

# obtain an access token:
curl -fsS -X POST http://localhost:8080/v1/auth/login \
  -H 'content-type: application/json' \
  -d '{"username":"admin","password":"<your ADMIN_BOOTSTRAP_PASSWORD>"}'
# -> {"access_token":"...","role":"admin","clearance":"restricted","expires_in":...}

export TOKEN="<access_token>"
```

Open the dashboard at <http://localhost:3000> and log in with the same
credentials. (Under the dev profile, `AUTH_MODE=dev` injects a synthetic admin
and these steps are optional.)

> If `/v1/auth/*` 404s, the governance auth layer (Stream A) is not deployed in
> your build yet; run the dev profile (`make up`) until it lands.

## 4. Add authorized scope (with an authorization note)

The safe seed (localhost + scanme.nmap.org) is one command:

```bash
make seed-scope
```

To add **your own** authorized asset, always include the `AUTH` note that
references your written authorization:

```bash
make scope-add KIND=subdomain_wildcard VALUE=yourdomain.example \
  AUTH="SOW-2026-014 §3, signed pentest authorization"
make scope-list
```

(Under the hardened profile, scope mutations require the admin token — add
`-H "Authorization: Bearer $TOKEN"` if you call the API directly instead of via
the Makefile.)

## 5. Kick off a full authorized recon scan

```bash
make scan KIND=full_recon TARGET=scanme.nmap.org
make scans-list
```

Watch it progress; the active worker politely probes (http fingerprint,
security headers, TLS posture, exposed-file sweep, port scan via naabu, nuclei
safe-tags only). Every outbound request is scope-checked and audited.

## 6. Read the results

```bash
# findings:
curl -fsS "http://localhost:8080/v1/findings?limit=100" | python3 -m json.tool
# the outbound audit trail (what the workers actually touched):
curl -fsS "http://localhost:8080/v1/scope/decisions?limit=100" | python3 -m json.tool
```

Or browse the dashboard: findings table, asset graph, chains, timeline.

## 7. Measure the false-positive rate

The FP harness runs the active worker's **safe** modules directly against an
authorized target and scores the output against a small hand-labeled truth set:

```bash
python3 hardening/realrun.py scanme.nmap.org
#   -> prints a triage table + crude FP rate + expected-signal recall
#   -> writes hardening/realrun_report.md
```

The harness **refuses** any target not in its authorized set and prints the
authorization reminder. If the ProjectDiscovery binaries or network egress are
unavailable it **degrades honestly** — it prints "could not execute live" plus
the exact commands above and writes a report saying so. It never invents a
finding or an FP number.

## 8. Verify the audit chain

```bash
make harden-check            # includes the live /v1/audit/verify call
# or directly:
curl -fsS http://localhost:8080/v1/audit/verify | python3 -m json.tool
#   -> {"ok": true, "checked": N}
```

## 9. Tear down

```bash
make down       # stop, keep data volumes
make nuke       # stop + delete volumes (DESTROYS all data)
```

---

### Quick reference

| Step | Command |
|---|---|
| secrets | `cp .env.example .env` then edit |
| up (dev) | `make up` |
| up (hardened) | `docker compose -f docker-compose.yml up -d --build` |
| seed safe scope | `make seed-scope` |
| add authorized scope | `make scope-add KIND=… VALUE=… AUTH="…"` |
| scan | `make scan KIND=full_recon TARGET=scanme.nmap.org` |
| findings | `curl .../v1/findings` |
| FP measurement | `python3 hardening/realrun.py scanme.nmap.org` |
| audit verify | `make harden-check` / `curl .../v1/audit/verify` |
| self-audit | `make harden-check` |
