#!/usr/bin/env bash
# Build the self-contained kit bundle: the sensor sources (standard library only)
# plus install.sh, the systemd units and the helper. Host the tarball anywhere
# you trust (your own server, S3, a release asset), then give its URL and the
# printed SHA-256 to the installer or to cloud-init.
#
#   deploy/sentry-kit/make-bundle.sh [OUT_DIR]      (default: ./dist)
set -euo pipefail
here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
repo="$(cd "$here/../.." && pwd)"
out="${1:-$PWD/dist}"
ver="$(sed -n 's/^__version__ = "\(.*\)"/\1/p' "$repo/sentry/paddock_sentry/__init__.py")"
work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT
stage="$work/paddock-sentry-kit-$ver"
mkdir -p "$stage" "$out"
cp -r "$repo/sentry/paddock_sentry" "$stage/paddock_sentry"
find "$stage" -name '__pycache__' -prune -exec rm -rf {} +
for f in install.sh prepare-iface.sh paddock-sentry.service paddock-sentry-firstboot.service paddock-sentry.env.example; do
  cp "$here/$f" "$stage/$f"
done
chmod 0755 "$stage/install.sh" "$stage/prepare-iface.sh"
tarball="$out/paddock-sentry-kit-$ver.tar.gz"
# reproducible: sorted names, fixed mtime/owner
tar --sort=name --mtime='2020-01-01 00:00:00' --owner=0 --group=0 --numeric-owner \
    -C "$work" -czf "$tarball" "paddock-sentry-kit-$ver"
sum="$(sha256sum "$tarball" | cut -d' ' -f1)"
echo "$sum  $(basename "$tarball")" > "$tarball.sha256"
echo "bundle: $tarball"
echo "sha256: $sum"
