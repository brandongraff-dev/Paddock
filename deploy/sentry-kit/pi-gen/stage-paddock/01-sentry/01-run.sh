#!/bin/bash -e
# pi-gen substage: bake the sensor into the image. build.sh has copied the kit
# files into ./files (sources + install.sh + units); nothing is downloaded here.
#
# ${ROOTFS_DIR} is the image root; `on_chroot` runs a command inside it.

install -d -m 0755 "${ROOTFS_DIR}/usr/local/lib/paddock-sentry"
cp -r files/paddock_sentry "${ROOTFS_DIR}/usr/local/lib/paddock-sentry/paddock_sentry"
for f in install.sh prepare-iface.sh paddock-sentry.service; do
	install -m 0755 "files/${f}" "${ROOTFS_DIR}/usr/local/lib/paddock-sentry/${f}"
done
install -m 0644 files/paddock-sentry-firstboot.service \
	"${ROOTFS_DIR}/etc/systemd/system/paddock-sentry-firstboot.service"

# The boot partition (mounted at /boot/firmware on Bookworm) gets an example the
# user copies, edits and renames: paddock-sentry.env
install -d "${ROOTFS_DIR}/boot/firmware"
install -m 0644 files/paddock-sentry.env.example "${ROOTFS_DIR}/boot/firmware/paddock-sentry.env.example"

on_chroot << EOF
# Runs once, on the first boot with network, only if paddock-sentry.env exists.
systemctl enable paddock-sentry-firstboot.service
# The first-boot user wizard would block a headless device.
systemctl disable userconfig.service 2>/dev/null || true
systemctl enable chrony.service 2>/dev/null || true
EOF

# The admin account is key-only: make the password unusable no matter what the
# config said (pi-gen requires FIRST_USER_PASS to be set).
on_chroot << EOF
passwd -l "${FIRST_USER_NAME}"
EOF
