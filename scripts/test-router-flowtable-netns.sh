#!/bin/sh
# Новые потоки видны NFQUEUE, длинные передачи возвращаются в flowtable.
set -eu

ROOT=$(CDPATH='' cd -- "$(dirname -- "$0")/.." && pwd)
if [ "${1:-}" != isolated ]; then
    exec unshare -n sh "$0" isolated
fi
TEMP=$(mktemp -d)
LAN="r2o-flow-lan-$$"
WAN="r2o-flow-wan-$$"
PIDS=
SERVER=
cleanup() {
    if [ -n "$SERVER" ]; then kill "$SERVER" 2>/dev/null || :; wait "$SERVER" 2>/dev/null || :; fi
    for pid in $PIDS; do kill "$pid" 2>/dev/null || :; done
    for pid in $PIDS; do wait "$pid" 2>/dev/null || :; done
    ip netns del "$LAN" 2>/dev/null || :
    ip netns del "$WAN" 2>/dev/null || :
    rm -rf "$TEMP"
}
trap cleanup EXIT
trap 'exit 1' HUP INT TERM

modprobe nfnetlink_queue
modprobe nft_queue
modprobe nft_flow_offload
R2OD=${R2O_DATAPATH_BIN:-"$ROOT/target/release/r2o-datapath"}
export R2O_DIR="$TEMP/r2o" R2O_RUN_DIR="$TEMP/run" R2O_CONFIG=/dev/null
export R2O_PLATFORM=openwrt FW_BACKEND=nft IPV6_ENABLED=1 CONNBYTES=0:8
export R2O_PLATFORM_RUNTIME=1 QUEUE_NUM=34000 QUEUE_NUM6=34001 MARK=45
export R2O_SOFTWARE_PATH_ENDPOINTS='' DNS_DISCOVERY_ENDPOINTS=''
unset PORTS

ip netns add "$LAN"
ip netns add "$WAN"
ip link add rlan type veth peer name client netns "$LAN"
ip link add rwan type veth peer name origin netns "$WAN"
ip addr add 192.0.2.1/24 dev rlan
ip addr add 198.18.0.1/24 dev rwan
ip -6 addr add 2001:db8:1::1/64 dev rlan nodad
ip -6 addr add 2001:db8:2::1/64 dev rwan nodad
ip link set rlan up
ip link set rwan up
ip -n "$LAN" addr add 192.0.2.2/24 dev client
ip -n "$WAN" addr add 198.18.0.2/24 dev origin
ip -n "$LAN" -6 addr add 2001:db8:1::2/64 dev client nodad
ip -n "$WAN" -6 addr add 2001:db8:2::2/64 dev origin nodad
ip -n "$LAN" link set client up
ip -n "$WAN" link set origin up
ip -n "$LAN" route add default via 192.0.2.1
ip -n "$WAN" route add default via 198.18.0.1
ip -n "$LAN" -6 route add default via 2001:db8:1::1
ip -n "$WAN" -6 route add default via 2001:db8:2::1
echo 1 >/proc/sys/net/ipv4/ip_forward
echo 1 >/proc/sys/net/ipv6/conf/all/forwarding

fw4_reload() {
    {
        if nft list table inet fw4 >/dev/null 2>&1; then echo 'delete table inet fw4'; fi
        cat <<'RULES'
table inet fw4 {
    flowtable ft { hook ingress priority filter; devices = { rlan, rwan }; }
    chain forward {
        type filter hook forward priority filter; policy accept;
        meta l4proto { tcp, udp } flow add @ft
    }
}
RULES
    } | nft -f -
}
platform() { "$R2OD" --platform "$@"; }
fw4_reload
nft -f - <<'RULES'
table inet visibility {
    counter tcp4 {}
    counter tcp6 {}
    counter udp4 {}
    counter udp6 {}
    counter other {}
    chain transit {
        type filter hook postrouting priority mangle - 1; policy accept;
        meta nfproto ipv4 tcp sport 443 meta length > 100 counter name tcp4
        meta nfproto ipv6 tcp sport 443 meta length > 100 counter name tcp6
        meta nfproto ipv4 udp sport 443 counter name udp4
        meta nfproto ipv6 udp sport 443 counter name udp6
        tcp sport 853 meta length > 100 counter name other
    }
}
RULES

for family in 4 6; do
    "$R2OD" --queue "$((33998 + family / 2))" --family "ipv$family" --mode apply \
        --mark "$MARK" --controller-only --control "$TEMP/control$family" --stats 0 \
        --r2o-flow-capacity 64 >"$TEMP/datapath$family.log" 2>&1 &
    PIDS="$PIDS $!"
done
for _ in $(seq 1 40); do
    [ ! -S "$TEMP/control4" ] || [ ! -S "$TEMP/control6" ] || break
    sleep 0.1
done
if ! platform up; then cat "$TEMP"/datapath*.log >&2; exit 1; fi
platform status
# Отдельный канал снимков обслуживается через тот же poll, даже без пакетов.
python3 - "$TEMP/control4.snapshot" <<'PY'
import socket
import sys

with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as sock:
    sock.settimeout(2)
    sock.connect(sys.argv[1])
    prefix = sock.recv(4, socket.MSG_WAITALL)
    assert len(prefix) == 4
    size = int.from_bytes(prefix, "big")
    assert 2 <= size <= 4096, (prefix.hex(), size)
    assert len(sock.recv(size, socket.MSG_WAITALL)) == size
PY
cat >"$TEMP/traffic.py" <<'PY'
import pathlib
import socket
import sys

role, address, proto, port, ready = sys.argv[1:]
addr = (address, int(port))
tcp = proto == "tcp"
family = socket.AF_INET6 if ":" in address else socket.AF_INET
data = b"abcdef0123456789" * 16
bulk = data * 16384
with socket.socket(family, socket.SOCK_STREAM if tcp else socket.SOCK_DGRAM) as sock:
    sock.settimeout(8)
    if role == "server":
        sock.bind(addr)
        if tcp:
            sock.listen(1)
        pathlib.Path(ready).touch()
        if tcp:
            conn, _ = sock.accept()
            with conn, conn.makefile("rb") as request:
                assert request.read(len(data)) == data
                conn.sendall(bulk)
        else:
            for _ in range(64):
                payload, source = sock.recvfrom(2048)
                assert payload == data
                sock.sendto(payload, source)
    else:
        sock.connect(addr)
        if tcp:
            sock.sendall(data)
            with sock.makefile("rb") as response:
                assert response.read(len(bulk)) == bulk
        else:
            for _ in range(64):
                sock.send(data)
                assert sock.recv(2048) == data
PY

transfer() {
    addr=$1 proto=$2 port=$3
    rm -f "$TEMP/ready"
    ip netns exec "$WAN" python3 "$TEMP/traffic.py" server "$addr" "$proto" "$port" "$TEMP/ready" &
    SERVER=$!
    for _ in $(seq 1 40); do
        [ ! -f "$TEMP/ready" ] || break
        sleep 0.1
    done
    ip netns exec "$LAN" python3 "$TEMP/traffic.py" client "$addr" "$proto" "$port" "$TEMP/ready"
    wait "$SERVER"
    SERVER=
}
counter() {
    nft list counter inet visibility "$1" | awk -v name="$1" -v min="$2" -v max="$3" -v field="$4" '
        /packets/ {print name, $0; ok = ($2 >= min && $field < max)}
        END {exit !ok}
    '
}

transfer 198.18.0.2 tcp 443
transfer 2001:db8:2::2 tcp 443
transfer 198.18.0.2 udp 443
transfer 2001:db8:2::2 udp 443
transfer 198.18.0.2 tcp 853
# При преждевременном offload данных нет. Если offload выключен, виден весь payload.
counter tcp4 2 1048576 4
counter tcp6 2 1048576 4
counter udp4 2 48 2
counter udp6 2 48 2
counter other 0 1048576 4
awk '
    $1 == 34000 || $1 == 34001 { if ($6 == 0 && $7 == 0 && $8 >= 8) ok++ }
    END { exit ok != 2 }
' /proc/net/netfilter/nfnetlink_queue

# Пересборка fw4 снимает защиту даже при исправном NFQUEUE. Событие возвращает её.
fw4_reload
if platform status; then exit 1; fi
platform event
for _ in $(seq 1 40); do
    if platform status >"$TEMP/status" 2>/dev/null; then break; fi
    sleep 0.1
done
grep -q '^fw4_admission=bounded$' "$TEMP/status"
nft -a list chain inet fw4 r2o_offload >"$TEMP/chain"
platform up
nft -a list chain inet fw4 r2o_offload | cmp "$TEMP/chain" -
platform down
nft list chain inet fw4 forward | grep -Eq 'flow (add|offload) @ft'
