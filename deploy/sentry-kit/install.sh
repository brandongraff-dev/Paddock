#!/usr/bin/env bash
# Paddock Sentry installer for Raspberry Pi OS / Debian / Ubuntu.
#
#   sudo ./install.sh                  # reads paddock-sentry.env from the boot partition
#   sudo ./install.sh --env /path/file # or from a file you choose
#
# What it does, in order (and nothing else):
#   1. reads PADDOCK_SERVER + PADDOCK_ENROLL_TOKEN from the env file
#   2. installs tcpdump + python3 from the distro (skipped if already present)
#   3. installs the sensor (Python standard library only) under /opt/paddock-sentry
#   4. creates the unprivileged `paddock-sentry` user and its state directory
#   5. picks the mirror/SPAN interface (or uses PADDOCK_SENTRY_IFACE) and tells
#      NetworkManager/dhcpcd not to configure it, so it stays silent
#   6. enrolls with your Paddock server, then removes the token from the env file
#   7. enables the systemd service
#
# It contacts only: your distro's package mirror (step 2) and your Paddock
# server (step 6 onward). No telemetry, no phoning home.
#
# Result is written to <boot>/paddock-sentry.status so you can read it by putting
# the SD card in another computer if the device has no screen.
set -euo pipefail

# --- test/CI seams (never needed in production) -------------------------------
ROOT="${PADDOCK_ROOT:-}"                 # prefix for every path we write
SKIP_APT="${PADDOCK_SKIP_APT:-0}"
SKIP_SYSTEMD="${PADDOCK_SKIP_SYSTEMD:-0}"
SKIP_USER="${PADDOCK_SKIP_USER:-0}"

KIT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
LIB_DIR="${ROOT}/opt/paddock-sentry"
STATE_DIR="${ROOT}/var/lib/paddock-sentry"
CONF_DIR="${ROOT}/etc/paddock-sentry"
BIN="${ROOT}/usr/local/bin/paddock-sentry"
HELPER_DIR="${ROOT}/usr/local/lib/paddock-sentry"
UNIT_DIR="${ROOT}/etc/systemd/system"
LOG="${ROOT}/var/log/paddock-sentry-install.log"
SVC_USER="paddock-sentry"

ENV_FILE=""
while [ $# -gt 0 ]; do
  case "$1" in
    --env) ENV_FILE="$2"; shift 2 ;;
    --firstboot) shift ;;
    -h|--help) sed -n '2,22p' "$0"; exit 0 ;;
    *) echo "unknown argument: $1" >&2; exit 2 ;;
  esac
done

mkdir -p "$(dirname "$LOG")"
exec > >(tee -a "$LOG") 2>&1

say() { printf '[paddock-sentry] %s\n' "$*"; }
status_file=""
write_status() {  # $1 = OK | FAILED, $2 = message
  local msg
  msg="$(date -u +%FT%TZ) $1: $2"
  [ -n "$status_file" ] && { printf '%s\n' "$msg" > "$status_file" 2>/dev/null || true; }
  say "$msg"
}
trap 'write_status FAILED "installer stopped at line $LINENO; see /var/log/paddock-sentry-install.log"' ERR

[ "$(id -u)" -eq 0 ] || [ -n "$ROOT" ] || { echo "run as root (sudo)" >&2; exit 1; }

# --- 1. read the env file safely (never `source` it: it comes from an SD card) ---
if [ -z "$ENV_FILE" ]; then
  for c in "${ROOT}/boot/firmware/paddock-sentry.env" "${ROOT}/boot/paddock-sentry.env" \
           "${CONF_DIR}/enroll.env"; do
    [ -f "$c" ] && { ENV_FILE="$c"; break; }
  done
fi
[ -n "$ENV_FILE" ] && [ -f "$ENV_FILE" ] || {
  echo "no paddock-sentry.env found. Put it on the boot partition, or pass --env FILE." >&2; exit 1; }
status_file="$(dirname "$ENV_FILE")/paddock-sentry.status"

get() {  # get KEY -> value of the last uncommented KEY=value line, quotes stripped
  local v
  v="$(tr -d '\r' < "$ENV_FILE" | grep -E "^[[:space:]]*$1=" | tail -n1 | sed -E "s/^[[:space:]]*$1=//; s/[[:space:]]+#.*$//; s/^[\"']//; s/[\"']$//" || true)"
  printf '%s' "${v%$'\r'}"
}
SERVER="$(get PADDOCK_SERVER)"
TOKEN="$(get PADDOCK_ENROLL_TOKEN)"
IFACE="$(get PADDOCK_SENTRY_IFACE)"
NAME="$(get PADDOCK_SENTRY_NAME)"
ALLOW_HTTP="$(get PADDOCK_ALLOW_HTTP)"

[[ "$SERVER" =~ ^https?://[A-Za-z0-9._:/-]+$ ]] || { write_status FAILED "PADDOCK_SERVER is missing or malformed"; exit 1; }
if [ -z "$TOKEN" ] && [ ! -f "${STATE_DIR}/credentials.json" ]; then
  write_status FAILED "PADDOCK_ENROLL_TOKEN is missing (create one in Paddock: Sensors > Add sensor)"; exit 1
fi
[[ -z "$TOKEN" || "$TOKEN" =~ ^pet_[0-9a-f]{8}_[A-Za-z0-9_-]+$ ]] || { write_status FAILED "PADDOCK_ENROLL_TOKEN is malformed"; exit 1; }
[[ -z "$IFACE" || "$IFACE" =~ ^[A-Za-z0-9._-]{1,15}$ ]] || { write_status FAILED "PADDOCK_SENTRY_IFACE is malformed"; exit 1; }
[[ -z "$NAME" || "$NAME" =~ ^[A-Za-z0-9._\ -]{1,64}$ ]] || { write_status FAILED "PADDOCK_SENTRY_NAME is malformed"; exit 1; }

# --- 2. packages -----------------------------------------------------------
if [ "$SKIP_APT" != "1" ]; then
  need=()
  command -v tcpdump  >/dev/null 2>&1 || need+=(tcpdump)
  command -v python3  >/dev/null 2>&1 || need+=(python3)
  [ -e /etc/ssl/certs/ca-certificates.crt ] || need+=(ca-certificates)
  if [ "${#need[@]}" -gt 0 ]; then
    say "installing: ${need[*]}"
    DEBIAN_FRONTEND=noninteractive apt-get update -qq
    DEBIAN_FRONTEND=noninteractive apt-get install -y -qq --no-install-recommends "${need[@]}"
  fi
fi

# --- 3. the sensor itself -------------------------------------------------------
SRC=""
for c in "$KIT_DIR/paddock_sentry" "$KIT_DIR/../../sentry/paddock_sentry" "${HELPER_DIR}/paddock_sentry"; do
  [ -d "$c" ] && { SRC="$c"; break; }
done
[ -n "$SRC" ] || { write_status FAILED "sensor sources not found next to install.sh (use the kit bundle)"; exit 1; }
mkdir -p "$LIB_DIR/lib" "$(dirname "$BIN")" "$HELPER_DIR"
rm -rf "$LIB_DIR/lib/paddock_sentry"
cp -r "$SRC" "$LIB_DIR/lib/paddock_sentry"
find "$LIB_DIR/lib" -name '__pycache__' -prune -exec rm -rf {} +
cat > "$BIN" <<'EOS'
#!/bin/sh
PYTHONPATH=/opt/paddock-sentry/lib exec python3 -m paddock_sentry.cli "$@"
EOS
chmod 0755 "$BIN"
[ -n "$ROOT" ] && sed -i "s#/opt/paddock-sentry/lib#${LIB_DIR}/lib#" "$BIN"
install -m 0755 "$KIT_DIR/prepare-iface.sh" "$HELPER_DIR/prepare-iface"

# --- 4. user + state ------------------------------------------------------------
if [ "$SKIP_USER" != "1" ]; then
  id "$SVC_USER" >/dev/null 2>&1 || useradd --system --no-create-home --home-dir "$STATE_DIR" \
      --shell /usr/sbin/nologin "$SVC_USER"
fi
install -d -m 0700 "$STATE_DIR" "$STATE_DIR/outbox"
install -d -m 0755 "$CONF_DIR"
[ "$SKIP_USER" = "1" ] || chown -R "$SVC_USER:$SVC_USER" "$STATE_DIR"

# --- 5. which port listens? -----------------------------------------------------
if [ -z "$IFACE" ]; then
  if IFACE="$("$BIN" pick-iface --explain 2>"$CONF_DIR/pick-iface.txt")"; then
    say "capture interface: $IFACE ($(cat "$CONF_DIR/pick-iface.txt"))"
  else
    write_status FAILED "could not pick the mirror port: $(cat "$CONF_DIR/pick-iface.txt"). Set PADDOCK_SENTRY_IFACE in paddock-sentry.env and reboot."
    exit 1
  fi
fi
# The capture port must never be configured by the OS: no DHCP, no IPv6 autoconf,
# nothing the sensor would have to say on the mirror port.
if [ -d "${ROOT}/etc/NetworkManager" ]; then
  mkdir -p "${ROOT}/etc/NetworkManager/conf.d"
  printf '[keyfile]\nunmanaged-devices=interface-name:%s\n' "$IFACE" \
    > "${ROOT}/etc/NetworkManager/conf.d/90-paddock-sentry.conf"
fi
if [ -f "${ROOT}/etc/dhcpcd.conf" ] && ! grep -q "paddock-sentry:$IFACE" "${ROOT}/etc/dhcpcd.conf"; then
  printf '\n# paddock-sentry:%s  (capture port: no address)\ndenyinterfaces %s\n' "$IFACE" "$IFACE" >> "${ROOT}/etc/dhcpcd.conf"
fi
{
  echo "PADDOCK_SENTRY_IFACE=$IFACE"
  echo "PADDOCK_SERVER=$SERVER"
} > "$CONF_DIR/sentry.env"
chmod 0644 "$CONF_DIR/sentry.env"

# --- 6. enroll ------------------------------------------------------------------
CRED="$STATE_DIR/credentials.json"
if [ -f "$CRED" ]; then
  say "already enrolled; keeping $CRED"
else
  args=(enroll --cred "$CRED")
  [ -n "$NAME" ] && args+=(--name "$NAME")
  [ "$ALLOW_HTTP" = "1" ] && args+=(--allow-http)
  runas=()
  [ "$SKIP_USER" = "1" ] || runas=(runuser -u "$SVC_USER" --)
  if ! PADDOCK_SERVER="$SERVER" PADDOCK_ENROLL_TOKEN="$TOKEN" "${runas[@]}" "$BIN" "${args[@]}"; then
    write_status FAILED "enrollment was refused or the server is unreachable (see above). Create a new token in Paddock (Sensors > Add sensor) and update paddock-sentry.env."
    exit 1
  fi
  # the token is spent; do not leave it on the SD card
  if [ -w "$ENV_FILE" ]; then
    sed -i -E "s/^([[:space:]]*PADDOCK_ENROLL_TOKEN=).*/# \1<used $(date -u +%F)>/" "$ENV_FILE" || true
  fi
fi

# --- 7. service -----------------------------------------------------------------
if [ "$SKIP_SYSTEMD" != "1" ]; then
  mkdir -p "$UNIT_DIR"
  install -m 0644 "$KIT_DIR/paddock-sentry.service" "$UNIT_DIR/paddock-sentry.service"
  systemctl daemon-reload
  systemctl enable --now paddock-sentry.service
fi
touch "$STATE_DIR/.installed"
write_status OK "sensor enrolled and running; capturing on $IFACE and reporting to $SERVER. It appears in Paddock under Sensors within a minute."
trap - ERR
exit 0
