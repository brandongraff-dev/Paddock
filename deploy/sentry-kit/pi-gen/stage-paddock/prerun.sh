#!/bin/bash -e
# pi-gen runs this before the stage's substages. Start from the previous stage's rootfs.
if [ ! -d "${ROOTFS_DIR}" ]; then
	copy_previous
fi
