# Sentry kit: set up a sensor in under an hour

Print this page. You need: a **Raspberry Pi 4/5** (or any small Debian/Ubuntu
box), a microSD card, **one extra USB Ethernet adapter**, two network cables and
a **managed switch** that can mirror a port (or a passive tap, see the end).

A Sentry sensor only listens. It sends nothing to your devices and nothing to
anyone except your own Paddock server. It reports *metadata* (who talked to whom,
on which port, how much, plus device announcements), never your traffic.

```
 router ── managed switch ── your devices
                │  ▲
   mirror port ─┘  └─ uplink / management
                │
   [ USB Ethernet ] ── Pi ── [ built-in Ethernet ] ── a normal port (reaches Paddock)
      listens only                 management
```

## 1. Get a token (2 minutes)

In Paddock: **Sensors → Add sensor**. Enter the site name, pick how long the
token lives, press *Create token*. The page shows the token **once**, with the
exact command and the `paddock-sentry.env` file for the SD card. A token works
one time and then it is spent; make one per sensor.

## 2. Pick one install path

### A. Flashable image (easiest, no typing on the Pi)

1. Build or download the image (`deploy/sentry-kit/pi-gen/`, see below) and flash it
   with **Raspberry Pi Imager → Use custom**.
2. Put the card back in your computer. On the small **boot** drive, create a file
   named **`paddock-sentry.env`** with the contents the wizard showed
   (`PADDOCK_SERVER=…`, `PADDOCK_ENROLL_TOKEN=…`).
3. Put the card in the Pi, connect **built-in port → normal switch port** and
   **USB adapter → the mirror port** (step 3), power on.
4. Within about two minutes the sensor appears under **Sensors**. If it does not,
   re-insert the card in your computer and read **`paddock-sentry.status`** on the
   boot drive: it says what went wrong in one line.

### B. Any Debian / Ubuntu / Raspberry Pi OS you already have

```bash
# on your workstation: build the bundle once and host it somewhere you trust
deploy/sentry-kit/make-bundle.sh                  # prints a SHA-256

# on the sensor: put paddock-sentry.env on /boot/firmware (or anywhere), then
curl -fsSLO https://files.example.com/paddock-sentry-kit-0.2.0.tar.gz
echo '<sha256>  paddock-sentry-kit-0.2.0.tar.gz' | sha256sum -c -
tar xzf paddock-sentry-kit-0.2.0.tar.gz && sudo ./paddock-sentry-kit-0.2.0/install.sh --env paddock-sentry.env
```

### C. cloud-init (fleets, Ubuntu, Raspberry Pi OS Trixie)

```bash
deploy/sentry-kit/cloud-init/render-user-data.sh \
  --server https://paddock.example.com:8101 --token pet_… \
  --bundle-url https://files.example.com/paddock-sentry-kit-0.2.0.tar.gz \
  --bundle-sha256 <sha256> > user-data
```

Put `user-data` (and `meta-data`) on the boot partition, or paste it into your
provider's user-data field. It installs `tcpdump`, verifies the bundle's SHA-256,
runs `install.sh` and enrolls.

**What the installer does, and nothing more:** installs `tcpdump` and `python3`
from your distro; copies the sensor to `/opt/paddock-sentry`; creates the
unprivileged `paddock-sentry` user; picks the mirror port (the wired port that has
a link and **no IP address**, or the one you set in `PADDOCK_SENTRY_IFACE`); stops
NetworkManager/dhcpcd from configuring it; enrolls with your server (then deletes
the spent token from the file); enables the systemd service. Its only network
contacts are your package mirror and your Paddock server. There is **no
telemetry**. The sensor's heartbeat is documented in `docs/SENTRY.md`
(counters about itself only).

Manual equivalent of the last step: `sudo paddock-sentry enroll https://paddock.example.com:8101 pet_…`
then `paddock-sentry doctor --iface eth1`.

## 3. Mirror a port on your switch

Mirror the **uplink** (the cable toward the router) to see everything, or the
ports of the IoT/OT VLAN to see just that. The sensor goes on the **destination**
port. Do not use the destination port for anything else, and do not mirror more
traffic than the destination port can carry (a Pi 4 copes with ~100 Mbit/s).
Menu names change between firmware versions; the idea is always *source ports →
destination port*.

| Switch | Where | Steps |
|---|---|---|
| **UniFi** (Network app) | *UniFi Devices → the switch → Ports* | Open the port the sensor is plugged into, set its **Operation** to **Mirror**, choose the **source port(s)** to copy, save/apply. (Some versions: *Port Manager → port → Port Mirroring*.) One mirror destination per switch. |
| **Cisco Meraki** | *Switching → Configure → Switch ports* | Edit the sensor's port: **Port mirroring → Destination port**. Edit each port to copy: **Port mirroring → Source port**, direction *Bidirectional*. One destination per switch; it must be on the same switch as the sources. |
| **TP-Link** Omada | *Devices → the switch → Ports → Mirroring* | Add a session: **mirroring port** = sensor port, **mirrored ports** = the ports to watch, direction *Both*. |
| **TP-Link** Easy Smart / JetStream (web UI) | *Monitoring → Port Mirror* (or *System → Port Mirror*) | Enable, set **Mirroring Port** = sensor port, tick the **Mirrored Port(s)**, direction **Both**, Apply. |
| **Netgear** Smart / Plus (e.g. GS308T, GS108Ev3) | *Monitoring → Mirroring* | Set **Port Mirroring** to *Enable*, **Destination Port** = sensor port, tick the **Source Ports**, direction *Tx and Rx*, Apply. |
| Cisco IOS, Aruba, MikroTik, VMware | see `docs/SENTRY.md` §1 | |

Check: plug the USB adapter into the mirror port; the Pi's port light should go
on but the sensor sends no traffic and the port gets no IP address. (If your
switch shows the sensor as a new device with an IP, the capture port was
configured by the OS: set `PADDOCK_SENTRY_IFACE` correctly and reboot.)

### No managed switch? Use a passive tap

Put a **network TAP** inline on the uplink (between the router and the switch).
Pick a **gigabit aggregating tap** (one monitor port carries both directions); a
cheap "throwing star" tap only works on 10/100 and gives you two one-way
monitor ports that need two adapters. The tap passes traffic even if powered
off (optical) or if the sensor is unplugged (copper, check the model's fail-open
note). Plug the monitor port into the sensor's USB adapter. Everything else is
the same as above.

## 4. Check it works

* **Sensors** page shows the sensor **online**, with a recent *last seen* and
  *last upload*. Devices appear under **Devices** after the first few windows (about a minute).
* On the sensor: `paddock-sentry doctor --iface eth1` (checks tcpdump, permissions,
  server, credential) and `paddock-sentry status`.
* Warnings on the Sensors page tell you what to fix: *packets dropped* (mirror a
  smaller set of ports), *buffer full* (the server was unreachable), *clock off*
  (fix NTP).

## If something goes wrong

| Symptom | Fix |
|---|---|
| `paddock-sentry.status` says token refused | Tokens are single-use and short-lived. Make a new one (Sensors → Add sensor), update the file. |
| "could not pick the mirror port" | Only one wired port, or several unnumbered ones. Add the USB adapter or set `PADDOCK_SENTRY_IFACE=eth1`. |
| Online but no devices | The mirror port is not copying traffic: re-check source ports and direction (*both*). |
| Sensor shows **silent** | Power, cable or the uplink to Paddock. Alerts (`sensor.offline`) can go to Slack/PagerDuty/email under **Integrations**. |
| Lost or stolen device | **Sensors → the sensor → Revoke.** Its credential stops working on its next request. |

## Building the flashable image (maintainers)

`deploy/sentry-kit/pi-gen/` is a [pi-gen](https://github.com/RPi-Distro/pi-gen)
stage layered on Raspberry Pi OS Lite. `SSH_PUBLIC_KEY="$(cat ~/.ssh/id_ed25519.pub)" deploy/sentry-kit/pi-gen/build.sh`
clones pi-gen (set `PIGEN_REF` to a commit you have reviewed), copies the stage and the
sensor sources into it, and runs the build (Docker or Debian host, ~1 h, ~15 GB). The
image is key-only SSH (password locked), has `tcpdump` and the sensor baked in, and a
`paddock-sentry-firstboot.service` that runs `install.sh` once when
`paddock-sentry.env` is present on the boot partition. The build has not been run in CI
(it needs a privileged container); the stage follows pi-gen's documented layout.
