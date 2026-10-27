#!/usr/bin/env bash
# Builds PC1 -> Device1 -> Device2 -> PC2 inside one Linux VM using network namespaces.
#   pc1 10.0.1.2 | d1 10.0.1.1 / 10.0.12.1 | d2 10.0.12.2 / 10.0.2.1 | pc2 10.0.2.2
# Protected service port: 5001 (everything else is forwarded untouched).
# Run as root:  sudo ./setup_lab.sh        (re-run to rebuild)
set -euo pipefail
PORT=5001

modprobe nfnetlink_queue || echo "WARN: nfnetlink_queue missing (apt install linux-modules-extra-\$(uname -r))"

for ns in pc1 d1 d2 pc2; do ip netns del $ns 2>/dev/null || true; ip netns add $ns; ip -n $ns link set lo up; done

ip link add v-pc1 type veth peer name v-d1a
ip link add v-d1b type veth peer name v-d2a
ip link add v-d2b type veth peer name v-pc2
ip link set v-pc1 netns pc1; ip link set v-d1a netns d1; ip link set v-d1b netns d1
ip link set v-d2a netns d2;  ip link set v-d2b netns d2; ip link set v-pc2 netns pc2

addr() { ip -n "$1" addr add "$2" dev "$3"; ip -n "$1" link set "$3" up; }
addr pc1 10.0.1.2/24  v-pc1
addr d1  10.0.1.1/24  v-d1a
addr d1  10.0.12.1/24 v-d1b
addr d2  10.0.12.2/24 v-d2a
addr d2  10.0.2.1/24  v-d2b
addr pc2 10.0.2.2/24  v-pc2

# Host-facing links get MTU 1480 so that payload + 16-byte tag still fits the 1500-byte device link.
for p in "pc1 v-pc1" "pc2 v-pc2"; do set -- $p; ip -n "$1" link set "$2" mtu 1480; done

ip -n pc1 route add default via 10.0.1.1
ip -n pc2 route add default via 10.0.2.1
ip -n d1  route add 10.0.2.0/24 via 10.0.12.2
ip -n d2  route add 10.0.1.0/24 via 10.0.12.1
ip netns exec d1 sysctl -qw net.ipv4.ip_forward=1
ip netns exec d2 sysctl -qw net.ipv4.ip_forward=1

# NFQUEUE sees whole packets only if offloads are off (otherwise GSO super-packets / partial checksums).
for pair in "pc1 v-pc1" "d1 v-d1a" "d1 v-d1b" "d2 v-d2a" "d2 v-d2b" "pc2 v-pc2"; do
  set -- $pair
  ip netns exec "$1" ethtool -K "$2" gro off gso off tso off tx off rx off >/dev/null 2>&1 || true
done

# queue 0 = encrypt, queue 1 = decrypt.  No listener => packets are dropped (fail closed).
ip netns exec d1 iptables -A FORWARD -i v-d1a -p tcp --dport $PORT -j NFQUEUE --queue-num 0
ip netns exec d1 iptables -A FORWARD -i v-d1b -p tcp --sport $PORT -j NFQUEUE --queue-num 1
ip netns exec d2 iptables -A FORWARD -i v-d2a -p tcp --dport $PORT -j NFQUEUE --queue-num 1
ip netns exec d2 iptables -A FORWARD -i v-d2b -p tcp --sport $PORT -j NFQUEUE --queue-num 0

echo "lab ready. Next:"
echo "  ip netns exec d2 env SECCHAN_PSK=secret ./secchan server 10.0.12.2 9000"
echo "  ip netns exec d1 env SECCHAN_PSK=secret ./secchan client 10.0.12.2 9000"
