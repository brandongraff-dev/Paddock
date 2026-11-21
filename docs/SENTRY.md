# Paddock Sentry: passive network sensor

Sentry gives Paddock eyes *inside* a network: every camera, printer,
thermostat, smart fridge, PLC and building controller, what it is, and
whether it is behaving like what it is. It is a small program (standard-
library Python plus `tcpdump`) that runs on a Raspberry Pi, a mini-PC, a VM
or a router, and listens to a **mirror (SPAN) port**.

## What it guarantees

- **Listen-only.** Sentry never sends a packet to, connects to, or probes a
  device. The only connection it may open is to your Paddock server, enforced
  at runtime by an egress guard and covered by tests.
- **Metadata, not content.** It ships flow summaries (who talked to whom, on
  which port, how much) and device announcements (DHCP / mDNS / SSDP). Payload
  bytes leave the sensor **only** for industrial protocols (Modbus, S7, DNP3,
  BACnet, EtherNet/IP, OPC-UA, ...), and only the first ~96 bytes of a few
  packets per flow, because identifying the protocol needs the header.
- **Survives outages.** If the server is unreachable it keeps a bounded
  on-disk outbox (default 256 MB) and catches up when the link returns.

## What you get

| Detector | Severity | Fires when |
|---|---|---|
| `device_lateral_scan` | high | an IoT/OT device initiates to ≥ 16 internal hosts, or ≥ 24 ports on one host, within 15 min |
| `ot_internet_egress` | high | an OT device (PLC, RTU, controller) initiates a connection to a public address |
| `iot_crosses_segment` | medium | an IoT device initiates to another internal segment on a non-infrastructure port |
| `cleartext_management` | medium | someone manages a device over Telnet / FTP / TFTP / SNMP v1-2c |
| `behavior_drift` | medium | after a 7-day learning period, a device *model* starts a kind of connection none of its kind made before |
| `ot_it_exposure`, `ot_public_exposure` | high | (existing) OT not isolated from IT, or on a public address |

Plus:

- device inventory (vendor, type, model, role: IT / IoT / OT)
- CVE matching for identified device models
- the **observed segmentation map**, which segments really reach which (`can_reach_observed` edges in the graph)

Baselines are learned per device **class** (vendor + type + model), not per
device. A second identical camera is protected the moment it appears.

## 1. Get a copy of the traffic

Pick one:

| Gear | How |
|---|---|
| **UniFi** | Devices → *switch* → Ports → *port* → Port Profile/Manage → **Port Mirroring**: mirror the uplink (or the IoT VLAN's ports) to the Sentry's port |
| **Cisco IOS** | `monitor session 1 source interface Gi1/0/1 both` · `monitor session 1 destination interface Gi1/0/24` |
| **Aruba / HPE** | `mirror-port 24` then `interface 1 monitor` (or a `mirror` session on CX) |
| **MikroTik** | Switch → Port settings → `mirror-source` / `mirror-target` |
| **VMware vSwitch** | Port group → Security → **Promiscuous mode: Accept**, run Sentry as a VM on that port group |
| **No managed switch** | an inexpensive passive network TAP inline on the uplink |
| **OpenWrt / router** | rotate captures into a directory (`tcpdump -G 60 -w /tmp/cap/%s.pcap`) and run Sentry with `--spool /tmp/cap` |

Mirror the **uplink of the segment you care about** (IoT VLAN, OT cell,
guest Wi-Fi bridge) for the best coverage. For a Raspberry Pi, add a USB
Ethernet adapter so one port mirrors and the other reaches the server.

## 2. Enroll the sensor

> The one-page version for non-experts, with a flashable image and switch-by-switch
> mirror-port steps, is the [Sentry kit guide](SENTRY_KIT.md).

Each sensor gets **its own credential**. In the dashboard open **Sensors → Add
sensor**, enter the site and an expiry, and copy the command (or the
`paddock-sentry.env` file for a first-boot SD card). Then on the sensor:

```bash
sudo paddock-sentry enroll https://paddock.example:8101 pet_xxxxxxxx_...
```

* The **enrollment token** (`pet_…`) is single-use (redeemed with one atomic
  update, so two sensors racing for it cannot both win), short-lived (5 minutes
  to 7 days, default 1 hour), stored only as a SHA-256, and revocable while
  unused. Wrong, expired, used and revoked tokens all get the same generic 401.
  Enrollment is rate-limited per client address (20/min) and locks an address
  out after 5 failures in 10 minutes (`SENSOR_ENROLL_PER_MIN`, `SENSOR_ENROLL_FAILS`;
  limits are per orchestrator replica).
* The server answers with a **per-sensor credential** (`pst_…`), shown once and
  stored only as a hash. The sensor writes it to
  `/var/lib/paddock-sentry/credentials.json` with mode 0600 (created atomically,
  refused on read if group/world accessible).
* `enroll` refuses plain `http://` to a non-local server unless `--allow-http`.
* **Revoking** a sensor (Sensors → the sensor → Revoke) takes effect on its very
  next request: nothing is cached anywhere. Revoking, token creation and enrollment
  are written to the audit log.
* Sensors belong to the tenant of the admin who created the token; their data is
  ingested into that tenant (multi-tenant installs need `SERVICE_API_KEY` set on
  otdiscovery so it can write on the tenant's behalf).

Sensors talk to **one address**: the `otdiscovery` port (8101), which fronts the
orchestrator for `/enroll`, `/heartbeat` and `/ingest`. Put it behind your TLS
reverse proxy (set `TRUST_PROXY=true` on otdiscovery only if that proxy sets
`X-Forwarded-For`, so rate limits see real client addresses).

**Legacy shared tokens** (`SENTRY_TOKENS=a,b`) still work for existing installs
and for `--token`; they have no per-sensor identity, health, revocation or batch
de-duplication. The hardened profile (`REQUIRE_SENTRY_TOKEN=true`) refuses data
from anything that is neither a valid per-sensor credential nor a listed token.
Set `MANAGED_SENSORS=false` to accept shared tokens only.

## 3. Run Sentry

After enrolling, `paddock-sentry run --iface eth1` is all it needs (server and
credential come from the credential file). The kit installs a systemd unit
([`deploy/sentry-kit/paddock-sentry.service`](../deploy/sentry-kit/paddock-sentry.service))
that runs as an unprivileged user with only `CAP_NET_RAW`/`CAP_NET_ADMIN`, brings
the capture port up silent (no IP, no IPv6, promiscuous) and restarts on failure.
The older unit at [`sentry/deploy/paddock-sentry.service`](../sentry/deploy/paddock-sentry.service)
is for shared-token installs.

**Docker** (amd64 / arm64), shared-token or an enrolled credential volume:

```bash
docker run -d --name paddock-sentry --restart unless-stopped \
  --network host --cap-drop ALL --cap-add NET_RAW --cap-add NET_ADMIN \
  --read-only --tmpfs /tmp -v paddock-sentry:/var/lib/paddock-sentry \
  paddock-sentry run --iface eth1
# first time only:  docker run --rm -v paddock-sentry:/var/lib/paddock-sentry paddock-sentry enroll https://paddock.example:8101 pet_...
```

**Bare metal**: `sudo apt install -y tcpdump python3-pip && sudo pip install ./sentry`, then
`paddock-sentry doctor --iface eth1`.

**Try it without hardware**: replay a capture and see exactly what would be sent.

```bash
paddock-sentry run --pcap capture.pcap --dry-run
```

## Resilience

* **Upload buffer.** Batches that cannot be delivered go to an on-disk buffer
  (gzip JSON, `/var/lib/paddock-sentry/outbox`) capped at `--outbox-max-mb`
  (default 256). When it is full the **oldest** batches are evicted first and
  counted (`batches_dropped`, shown as a warning in the dashboard).
* **Backoff and resume.** After a failure the sensor backs off exponentially
  (5 s doubling to 5 min, ±25% jitter) and meanwhile only buffers, never blocking
  capture. The heartbeat doubles as a probe: the first answer drains the buffer
  oldest-first, even on a quiet link.
* **Compression.** Uploads are gzip (`Content-Encoding: gzip`).
* **Exactly-once accounting.** Every batch has a `batch_id` (sent as
  `Idempotency-Key`). The server records it per sensor: a replay after a lost
  reply is acknowledged (`{"duplicate": true}`) and not applied again; a batch
  whose processing failed is released and accepted on retry; a concurrent retry gets
  409. Batch ids are kept `SENSOR_BATCH_RETENTION_DAYS` (3).
* A `400/413/422` batch is dropped (retrying cannot help); `401/403` stops
  uploads and logs that the credential was revoked or wrong.

## Health and alerts

Every 60 s the sensor POSTs `/heartbeat`. **That is the only telemetry it sends**,
and it contains exactly: the sensor version and its NIC list (name, link, speed,
MAC), `uptime_s`, `packets_seen`, `packets_dropped` (NIC/kernel receive drops
since start), `flows_dropped`, `buffer_fill_pct/bytes/batches`, `batches_dropped`,
`last_upload_ts/ok`, the capture interface name and its own clock (so the server
shows skew). Never traffic, never addresses of observed devices.

The **Sensors** page shows state (*online*, *needs attention* for drops, a nearly
full buffer, evicted batches or more than 30 s of clock skew, *silent*, *revoked*),
last seen, last upload, and the health counters. A sensor with no contact for
`silent_after_s` (default 300, set per sensor, `SENSOR_SILENT_AFTER_S`) is marked
silent and raises the integration event **`sensor.offline`** (severity high) once;
the first contact afterwards raises **`sensor.online`**. Route them to Slack,
PagerDuty, email or a SIEM like any other event (see [Integrations](INTEGRATIONS.md)).
`GET :8101/metrics` still exports `paddock_sentry_last_ingest_timestamp_seconds` for Prometheus.

## 4. Check it is working

- `paddock-sentry doctor` checks tcpdump, interface, permissions, enrollment and
  server reachability; `paddock-sentry status` shows the buffer.
- `GET http://<server>:8101/stats` shows each sensor's `last_seen`, batch
  count and last window (packets, flows, dropped flows).
- Devices appear in the dashboard under **Devices**. Behaviour findings
  appear under **Findings** with `rule_source = policy` and
  `detector = device_lateral_scan | ...`.

## Sizing

- **Bandwidth to the server:** one batch every 30 s. A busy 200-device
  office produces roughly 1–3k flows per window, about 100–300 KB per batch
  before compression.
- **Capture:** a Raspberry Pi 4 comfortably handles a ~100 Mbit/s mirror.
  Beyond that, use a mini-PC, or mirror only the IoT/OT VLANs.
- **Memory:** bounded by `--window` and the flow table cap (50k flows per
  window).

## Server-side tuning (otdiscovery environment)

| Variable | Default | Meaning |
|---|---|---|
| `SENTRY_TOKENS` | — | legacy shared sensor tokens |
| `MANAGED_SENSORS` | `true` | accept per-sensor credentials (verified by the orchestrator) |
| `MANAGED_ANALYZE_INTERVAL_S` | 15 | analysis runs at most once per interval per tenant |
| `TRUST_PROXY` | `false` | read the client address from `X-Forwarded-For` |
| `REQUIRE_SENTRY_TOKEN` | `true` (hardened) | refuse ingest when no tokens are configured |
| `BEHAVIOR_WINDOW_S` | 900 | look-back for scan / egress detection |
| `SCAN_HOSTS` / `SCAN_PORTS` | 16 / 24 | lateral-scan thresholds |
| `BASELINE_LEARN_S` | 604800 | learning period per device class |
| `BASELINE_PATH` | `/var/lib/otdiscovery/baselines.json` | where learned profiles persist |
| `FLOW_RETENTION_S` / `MAX_OBSERVATIONS` | 3600 / 200000 | memory bounds |

Orchestrator-side: `SENSOR_SILENT_AFTER_S` (300), `SENSOR_HEARTBEAT_S` (60),
`SENSOR_MONITOR_INTERVAL_S` (30), `SENSOR_BATCH_RETENTION_DAYS` (3),
`SENSOR_ENROLL_PER_MIN` (20), `SENSOR_ENROLL_FAILS` (5), `SENSOR_HEARTBEAT_PER_MIN` (30).

## Scale

`hardening/sentry_scale.py` drives 100 simulated sensors through the real path
(HTTP → otdiscovery → orchestrator → Postgres 16) at 1,000,000 flows/day
(11.6/s) with a 50× burst for a minute, replays 2% of batches, and reconciles
the server's counters against what was sent. Run it from Actions → *Scale test* →
`sentry_scale`, or locally (see the script's header).

100 simulated sensors, 30 devices each, 1,000,000 flows/day equivalent (11.6/s), 30s windows, burst x50, 2% of batches replayed with the same batch id.

| Phase | Flows/s | Batches/s | Requests | p50 ms | p95 ms | p99 ms | max ms | Errors | otdiscovery CPU |
|---|---:|---:|---:|---:|---:|---:|---:|---|---:|
| steady x1 | 11.4 | 3.33 | 304 | 19.5 | 41.4 | 79.1 | 240.2 | none | 2.0% |
| burst x50 | 575.3 | 3.33 | 205 | 62.3 | 155.5 | 232.3 | 329.8 | none | 12.9% |
| recover x1 | 11.7 | 3.33 | 205 | 73.1 | 182.7 | 232.7 | 273.6 | none | 20.1% |

| Table | Rows added | Size added |
|---|---:|---:|
| database total |  | 489.5 KiB |
| sensor_batches | 700 | 224.0 KiB |
| assets | 32 | 160.0 KiB |
| sensors | 0 | 64.0 KiB |
| asset_edges | 30 | 48.0 KiB |
| audit_log | 56 | 32.0 KiB |
| findings | 0 | 0.0 B |
| integration_deliveries | 0 | 0.0 B |
| agent_actions | 0 | 0.0 B |

Projection at this batch rate (per day): batch rows per day 288,000, sensor batches bytes per day 90.0 MiB, audit log bytes per day 12.9 MiB, db bytes per day total 196.7 MiB

Measured on a shared 2-core dev VM (everything on one machine, Postgres 16, 90 s
steady / 60 s 50x burst / 60 s recovery, real 30 s windows). Server counters matched
what was sent exactly (36,247 flows, 700 batches, 14 replays acknowledged without
double counting, all 100 sensors online).

What the first run found, and the fixes:

* **Analysis was O(stored flows) per upload and blocked the event loop**: about
  0.17 ms per stored observation, so ~6 s per upload at one hour of 1M-flows/day
  traffic; the test never finished. Now repeated flows are merged on arrival (storage
  and analysis grow with *distinct* flows, not flow events), MAC/IP parsing is cached,
  analysis for managed sensors runs at most once per `MANAGED_ANALYZE_INTERVAL_S` per
  tenant in a worker thread, and uploads return as soon as the data is stored.
* **audit_log growth**: the write-ahead audit of every heartbeat/claim/done was ~90% of
  database growth (about 0.85 GiB/day at 100 sensors). Successful routine sensor calls
  are no longer audited per request; failures, denials and every lifecycle action
  (token create/revoke, enroll, sensor update/revoke) still are.
* Flows themselves are never stored in Postgres; growth is devices, edges, findings,
  audit and `sensor_batches` (about 90 MiB/day at 100 sensors, purged after 3 days).

Limits worth knowing: analysis state is in otdiscovery memory (bounded by
`MAX_OBSERVATIONS`, per tenant), so run one otdiscovery replica per ingest address (or
shard sensors by tenant); the enrollment rate limiter is per orchestrator replica.
