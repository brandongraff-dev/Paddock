#!/usr/bin/env bash
# Fill user-data.template. Writes the result to stdout; refuses malformed input so
# a typo cannot end up as shell in a cloud-init file.
#
#   ./render-user-data.sh --server URL --token pet_... --bundle-url URL --bundle-sha256 HEX [--name NAME]
set -euo pipefail
here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
server="" token="" burl="" bsha="" name="paddock-sentry"
while [ $# -gt 0 ]; do
  case "$1" in
    --server) server="$2"; shift 2 ;;
    --token) token="$2"; shift 2 ;;
    --bundle-url) burl="$2"; shift 2 ;;
    --bundle-sha256) bsha="$2"; shift 2 ;;
    --name) name="$2"; shift 2 ;;
    *) echo "unknown argument: $1" >&2; exit 2 ;;
  esac
done
[[ "$server" =~ ^https://[A-Za-z0-9._:/-]+$ ]] || { echo "--server must be an https:// URL" >&2; exit 2; }
[[ "$token" =~ ^pet_[0-9a-f]{8}_[A-Za-z0-9_-]+$ ]] || { echo "--token is not a Paddock enrollment token (pet_...)" >&2; exit 2; }
[[ "$burl" =~ ^https://[A-Za-z0-9._:/~%+-]+$ ]] || { echo "--bundle-url must be an https:// URL" >&2; exit 2; }
[[ "$bsha" =~ ^[0-9a-f]{64}$ ]] || { echo "--bundle-sha256 must be 64 hex chars (make-bundle.sh prints it)" >&2; exit 2; }
[[ "$name" =~ ^[A-Za-z0-9._-]{1,63}$ ]] || { echo "--name may contain letters, digits, . _ -" >&2; exit 2; }
sed -e "s|@PADDOCK_SERVER@|$server|g" -e "s|@ENROLL_TOKEN@|$token|g" \
    -e "s|@BUNDLE_URL@|$burl|g" -e "s|@BUNDLE_SHA256@|$bsha|g" -e "s|@SENSOR_NAME@|$name|g" \
    "$here/user-data.template"
