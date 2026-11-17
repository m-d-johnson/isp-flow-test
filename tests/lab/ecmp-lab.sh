#!/usr/bin/env bash
# ECMP fault lab: network namespaces that reproduce a per-flow fault, for tests and demos.
#
#                       ┌── ra ──┐
#   cl ── r1 (ECMP, L4) ┤        ├── r2 ── srv  10.0.9.2 (test target, behind the split)
#          │            └── rb ──┘
#          └── ctl 10.0.8.2 (control, no split)
#
# r1 and r2 hash each flow's 5-tuple onto ra or rb (fib_multipath_hash_policy=3, Linux 5.12+). rb's
# link back towards r1 is rate-limited, like a faulty LAG/ECMP member, so roughly half of
# all downloads from srv crawl while the rest run at full speed. Downloads from ctl never
# cross the split.
#
# Usage (root): ecmp-lab.sh up | down | exec <cmd...>   (exec runs inside the client namespace)
# Needs: iproute2 (ip, tc), python3. Linux only.
set -euo pipefail

P=${LAB_PREFIX:-efl}                 # namespace name prefix, so parallel labs don't collide
RATE=${LAB_BAD_RATE:-8mbit}          # the faulty member's rate
FILE_SIZE=${LAB_FILE_SIZE:-4G}       # sparse test file served by srv and ctl
WWW=${LAB_WWW:-/tmp/$P-www}
NS=(cl r1 ra rb r2 srv ctl)

ns() { echo "$P-$1"; }
x() { ip netns exec "$(ns "$1")" "${@:2}"; }

link() {   # link <nsA> <ifA> <addrA> <nsB> <ifB> <addrB>
  ip link add "$2" netns "$(ns "$1")" type veth peer name "$5" netns "$(ns "$4")"
  ip -n "$(ns "$1")" addr add "$3" dev "$2"; ip -n "$(ns "$1")" link set "$2" up
  ip -n "$(ns "$4")" addr add "$6" dev "$5"; ip -n "$(ns "$4")" link set "$5" up
}

up() {
  down 2>/dev/null || true
  for n in "${NS[@]}"; do
    ip netns add "$(ns "$n")"
    ip -n "$(ns "$n")" link set lo up
    x "$n" sysctl -qw net.ipv4.ip_forward=1 net.ipv4.icmp_ratelimit=0
    # Hash on the 5-tuple from the headers (policy 3, fields src/dst address, protocol, src/dst
    # port), as real routers do. Policy 1 would reuse the skb's socket hash, which veth carries over
    # from the sending host and which is random per connection, so a fixed source port would not
    # stick to one member.
    x "$n" sysctl -qw net.ipv4.fib_multipath_hash_policy=3 net.ipv4.fib_multipath_hash_fields=0x0037
  done
  link cl  c0   10.0.1.2/24  r1 r1c  10.0.1.1/24
  link r1  r1a  10.0.2.1/24  ra ra1  10.0.2.2/24
  link r1  r1b  10.0.3.1/24  rb rb1  10.0.3.2/24
  link ra  ra2  10.0.4.1/24  r2 r2a  10.0.4.2/24
  link rb  rb2  10.0.5.1/24  r2 r2b  10.0.5.2/24
  link r2  r2s  10.0.9.1/24  srv s0  10.0.9.2/24
  link r1  r1t  10.0.8.1/24  ctl t0 10.0.8.2/24

  ip -n "$(ns cl)"  route add default via 10.0.1.1
  ip -n "$(ns srv)" route add default via 10.0.9.1
  ip -n "$(ns ctl)" route add default via 10.0.8.1
  ip -n "$(ns r1)"  route add 10.0.9.0/24 nexthop via 10.0.2.2 nexthop via 10.0.3.2
  ip -n "$(ns r2)"  route add 10.0.1.0/24 nexthop via 10.0.4.1 nexthop via 10.0.5.1
  for m in ra rb; do
    ip -n "$(ns $m)" route add 10.0.1.0/24 via "10.0.$([ $m = ra ] && echo 2 || echo 3).1"
    ip -n "$(ns $m)" route add 10.0.9.0/24 via "10.0.$([ $m = ra ] && echo 4 || echo 5).2"
  done

  # the faulty member: rb's egress back towards r1 (the download direction)
  x rb tc qdisc add dev rb1 root tbf rate "$RATE" burst 32kbit latency 400ms

  mkdir -p "$WWW"
  [ -f "$WWW/big.bin" ] || truncate -s "$FILE_SIZE" "$WWW/big.bin"
  for s in srv ctl; do
    x "$s" python3 -m http.server 80 --bind 0.0.0.0 --directory "$WWW" >/dev/null 2>&1 &
    echo $! > "/tmp/$P-$s.pid"
  done
  for i in $(seq 1 50); do
    x cl python3 - 2>/dev/null <<'EOF' && break || sleep 0.2
import socket
for ip in ("10.0.9.2", "10.0.8.2"):
    socket.create_connection((ip, 80), 1).close()
EOF
  done
  echo "lab up: test target http://10.0.9.2/big.bin, control http://10.0.8.2/big.bin"
}

down() {
  for s in srv ctl; do
    [ -f "/tmp/$P-$s.pid" ] && kill "$(cat "/tmp/$P-$s.pid")" 2>/dev/null || true
    rm -f "/tmp/$P-$s.pid"
  done
  for n in "${NS[@]}"; do ip netns del "$(ns "$n")" 2>/dev/null || true; done
}

case "${1:-}" in
  up) up ;;
  down) down ;;
  exec) shift; x cl "$@" ;;
  *) echo "usage: $0 up|down|exec <cmd...>" >&2; exit 2 ;;
esac
