---
name: Bug report
about: Something is broken or behaves unexpectedly
title: "[bug] "
labels: ["bug"]
---

<!--
Thanks for the report. Before filing:
 • Do NOT include output from scans of a real/production target you don't fully
   control. Reproduce against the demo graph (`make demo`) or scanme.nmap.org.
 • Do NOT paste secrets, `.env` contents, API keys, or JWTs.
 • Security vulnerabilities in Paddock itself: see SECURITY.md — report
   privately, do not open a public issue.
-->

## What happened

A clear description of the bug.

## Expected

What you expected instead.

## Steps to reproduce

1.
2.
3.

## Which part

- [ ] orchestrator / API
- [ ] a worker (passive / active)
- [ ] correlation / chains / attack paths
- [ ] intel / SCA / threat-intel / code analysis
- [ ] ml-risk / changewatch / triage / ontology / graphsync
- [ ] dashboard (UI)
- [ ] compose / setup / docs
- [ ] not sure

## Environment

- Paddock version / commit:
- Profile: `make up` (dev) / `docker compose -f docker-compose.yml` (hardened)
- OS + Docker / Compose versions:

## Logs / evidence

<details>
<summary>relevant logs (`make logs-<service>`)</summary>

```
paste here — scrub hosts/secrets
```

</details>
