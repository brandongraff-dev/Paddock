#!/usr/bin/env bash
# Build a flashable Paddock Sentry image with pi-gen (Raspberry Pi OS Lite base).
#
#   SSH_PUBLIC_KEY="$(cat ~/.ssh/id_ed25519.pub)" ./build.sh
#
# Needs Docker (or a Debian host: see pi-gen's README) and about 15 GB free.
# Result: pi-gen/deploy/*paddock-sentry*.img.xz  ->  flash with Raspberry Pi Imager
# ("Use custom"), then add paddock-sentry.env to the boot partition (see docs/SENTRY_KIT.md).
#
# This script is not run in CI (it needs a privileged container and ~an hour); it
# follows pi-gen's documented stage layout. Pin PIGEN_REF to a commit you have reviewed.
set -euo pipefail
here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
repo="$(cd "$here/../../.." && pwd)"
work="${WORK_DIR:-$PWD/pi-gen-work}"
ref="${PIGEN_REF:-bookworm-arm64}"        # 64-bit Pi 3/4/5/Zero 2; use "bookworm" for 32-bit Pi Zero/1/2

: "${SSH_PUBLIC_KEY:?set SSH_PUBLIC_KEY to the public key allowed to log in as the admin user}"
case "$SSH_PUBLIC_KEY" in ssh-ed25519\ *|ssh-rsa\ *|ecdsa-sha2-*) ;; *) echo "SSH_PUBLIC_KEY does not look like a public key" >&2; exit 2 ;; esac
[[ "$SSH_PUBLIC_KEY" != *'"'* && "$SSH_PUBLIC_KEY" != *'$'* && "$SSH_PUBLIC_KEY" != *'`'* ]] \
  || { echo "SSH_PUBLIC_KEY contains shell metacharacters" >&2; exit 2; }

if [ ! -d "$work/.git" ]; then
  git clone --depth 1 --branch "$ref" https://github.com/RPi-Distro/pi-gen.git "$work"
fi
cd "$work"

# our stage, with the kit files it bakes in
rm -rf stage-paddock
cp -r "$here/stage-paddock" stage-paddock
files="stage-paddock/01-sentry/files"
mkdir -p "$files"
cp -r "$repo/sentry/paddock_sentry" "$files/paddock_sentry"
find "$files" -name '__pycache__' -prune -exec rm -rf {} +
for f in install.sh prepare-iface.sh paddock-sentry.service paddock-sentry-firstboot.service paddock-sentry.env.example; do
  cp "$repo/deploy/sentry-kit/$f" "$files/$f"
done
chmod +x stage-paddock/prerun.sh stage-paddock/01-sentry/01-run.sh

# stages 3-5 (desktop) are not part of a sensor; stage2 must not export its own image
touch stage3/SKIP stage4/SKIP stage5/SKIP stage4/SKIP_IMAGES stage5/SKIP_IMAGES stage2/SKIP_IMAGES

pw="$(head -c 32 /dev/urandom | base64 | tr -d '/+=' | cut -c1-24)"
sed -e "s|@SSH_PUBLIC_KEY@|$SSH_PUBLIC_KEY|" -e "s|@RANDOM_PASSWORD@|$pw|" \
    "$here/config.example" > config

if command -v docker >/dev/null 2>&1; then
  ./build-docker.sh
else
  sudo ./build.sh
fi
ls -lh deploy/
