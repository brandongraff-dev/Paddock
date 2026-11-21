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

## 2. Enable sensor ingest on the server

```bash
# .env on the Paddock server
SENTRY_TOKENS=<token-for-sensor-1>,<token-for-sensor-2>
```

Generate one token per sensor:

```bash
python3 -c "import secrets;print(secrets.token_urlsafe(32))"
```

The hardened profile **refuses all sensor data** until `SENTRY_TOKENS` is
set. The ingest endpoint is `otdiscovery` on port **8101**; put it behind your
TLS reverse proxy.

## 3. Run Sentry

**Docker** (amd64 / arm64):

```bash
docker run -d --name paddock-sentry --restart unless-stopped \
  --network host --cap-drop ALL --cap-add NET_RAW --cap-add NET_ADMIN \
  --read-only --tmpfs /tmp -v paddock-sentry:/var/lib/paddock-sentry \
  -e PADDOCK_SERVER=https://paddock.example:8101 \
  -e PADDOCK_SENTRY_TOKEN=<token> -e PADDOCK_SITE=store-42 \
  paddock-sentry run --iface eth1
```

Build the image from `sentry/` with `docker build -t paddock-sentry sentry/`.

**Bare metal / Raspberry Pi OS**:

```bash
sudo apt install -y tcpdump python3-pip
sudo pip install ./sentry          # provides `paddock-sentry`
paddock-sentry doctor --iface eth1 --server https://paddock.example:8101 --token <token>
```

The systemd unit at [`sentry/deploy/paddock-sentry.service`](../sentry/deploy/paddock-sentry.service)
runs Sentry with only `CAP_NET_RAW`/`CAP_NET_ADMIN`.

**Try it without hardware**: replay a capture and see exactly what would be
sent.

```bash
paddock-sentry run --pcap capture.pcap --dry-run
```

## 4. Check it is working

- `paddock-sentry doctor` checks tcpdump, interface, permissions, server
  reachability and token.
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
| `SENTRY_TOKENS` | — | accepted sensor tokens |
| `REQUIRE_SENTRY_TOKEN` | `true` (hardened) | refuse ingest when no tokens are configured |
| `BEHAVIOR_WINDOW_S` | 900 | look-back for scan / egress detection |
| `SCAN_HOSTS` / `SCAN_PORTS` | 16 / 24 | lateral-scan thresholds |
| `BASELINE_LEARN_S` | 604800 | learning period per device class |
| `BASELINE_PATH` | `/var/lib/otdiscovery/baselines.json` | where learned profiles persist |
| `FLOW_RETENTION_S` / `MAX_OBSERVATIONS` | 3600 / 200000 | memory bounds |
