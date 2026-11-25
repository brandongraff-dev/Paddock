set -e
nft -f - <<'R'
table inet filter {
  set trusted { type ipv4_addr; flags interval; elements = { 10.0.0.0/8, 192.168.1.0/24 } }
  chain input {
    type filter hook input priority 0; policy drop;
    iif lo accept
    ct state established,related accept
    ct state invalid drop
    ip saddr 10.0.0.0/8 tcp dport 22 accept
    ip saddr @trusted tcp dport { 80, 443 } accept
    tcp dport 8000-8100 accept
    ip6 nexthdr icmpv6 accept
    meta mark 0x1 accept
    counter drop
  }
  chain forward { type filter hook forward priority 0; policy drop; }
}
R
echo "== nft list ruleset"; nft list ruleset
echo "== nft -j"; nft -j list ruleset
echo "== iptables-save"; iptables-save || true
