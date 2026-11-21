#!/bin/sh
# Run by systemd (as root, before the sensor starts) to bring the capture port up
# SILENT: link up, promiscuous, no IPv6 (so the kernel never sends router/
# neighbour solicitations or MLD reports onto the mirror port), no address.
#
#   prepare-iface eth1
set -eu
IF="${1:?usage: prepare-iface IFACE}"
case "$IF" in *[!A-Za-z0-9._-]*|"") echo "bad interface name" >&2; exit 2 ;; esac
[ -d "/sys/class/net/$IF" ] || { echo "interface $IF does not exist" >&2; exit 1; }

# 1. no IPv6 at all on this port (must happen BEFORE the link comes up)
sysctl -qw "net.ipv6.conf.$IF.disable_ipv6=1" 2>/dev/null || true
# 2. no addresses, in case something configured one
ip -4 addr flush dev "$IF" 2>/dev/null || true
ip -6 addr flush dev "$IF" 2>/dev/null || true
# 3. link up, receive everything the switch copies to us, never answer ARP
ip link set dev "$IF" up promisc on arp off 2>/dev/null \
  || ip link set dev "$IF" up promisc on
exit 0
