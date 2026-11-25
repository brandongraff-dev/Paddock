iptables -P INPUT DROP 2>&1
iptables -A INPUT -i lo -j ACCEPT
iptables -A INPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
iptables -A INPUT -p tcp -s 10.0.0.0/8 --dport 22 -j ACCEPT
iptables -A INPUT -p tcp -m multiport --dports 80,443 -j ACCEPT
iptables -A INPUT -p tcp -m set --match-set trusted src --dport 5432 -j ACCEPT 2>&1 | head -2
iptables -A INPUT -p tcp -m mark --mark 1 -j ACCEPT 2>&1 | head -2
iptables -N DOCKER-USER; iptables -A INPUT -j DOCKER-USER; iptables -A DOCKER-USER -j RETURN
iptables -A INPUT -p tcp --dport 8000:8100 -m comment --comment web -j ACCEPT
iptables -A INPUT ! -s 192.0.2.0/24 -p udp --dport 53 -j ACCEPT
echo "== iptables-save"; iptables-save
echo "== iptables -S"; iptables -S
echo "== ip6tables-save"; ip6tables-save 2>&1 | head
