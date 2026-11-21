#!/bin/sh
# Проверка маршрутов DNS в отдельном сетевом пространстве, без рабочих правил роутера.
set -eu

ROOT=$(CDPATH='' cd -- "$(dirname -- "$0")/.." && pwd)
if [ "${1:-}" != isolated ]; then
    exec unshare -n sh "$0" isolated
fi

WORK=$(mktemp -d)
peer=
cleanup() {
    if [ -n "$peer" ]; then kill "$peer" 2>/dev/null || :; wait "$peer" 2>/dev/null || :; fi
    rm -rf -- "$WORK"
}
trap cleanup EXIT HUP INT TERM

export R2O_DIR="$WORK" R2O_CONFIG=/dev/null R2O_RUN_DIR="$WORK/run"
export FW_BACKEND=${FW_BACKEND:-nft} QUEUE_NUM=34000 QUEUE_NUM6=34001 MEASURE_MARK=47
export R2O_PPE_DEOFFLOAD=0
FIREWALL="$ROOT/router/r2o-firewall.sh"

ip link set lo up
sysctl -qw net.netfilter.nf_conntrack_acct=1
unshare -n sh -c 'echo ready > "$1"; exec sleep 60' sh "$WORK/peer" &
peer=$!
for _ in 1 2 3 4 5 6 7 8 9 10; do
    [ ! -e "$WORK/peer" ] || break
    sleep 0.05
done
test -e "$WORK/peer"
ip link add dnsc type veth peer name dnss
ip link set dnss netns "$peer"
ip addr add 192.0.2.1/24 dev dnsc
ip -6 addr add 2001:db8::1/64 dev dnsc nodad
ip link set dnsc up
nsenter -n -t "$peer" ip addr add 192.0.2.2/24 dev dnss
nsenter -n -t "$peer" ip -6 addr add 2001:db8::2/64 dev dnss nodad
nsenter -n -t "$peer" ip link set dnss up

sh "$FIREWALL" up
sh "$FIREWALL" status
sh "$FIREWALL" dns-route add 192.0.2.2 udp 853 20
sh "$FIREWALL" dns-route add 2001:db8::2 udp 853 20
sh "$FIREWALL" dns-route add 2001:db8::2 udp 853 40
if sh "$FIREWALL" dns-route add 192.0.2.2 udp 53 20; then exit 1; fi
if sh "$FIREWALL" dns-route add ::1 tcp 853 20; then exit 1; fi

nsenter -n -t "$peer" python3 - "$WORK/server" <<'PY' &
import pathlib
import selectors
import socket
import sys

with selectors.DefaultSelector() as monitor:
    for family, address in [(socket.AF_INET, "192.0.2.2"), (socket.AF_INET6, "2001:db8::2")]:
        for port in [853, 854]:
            listener = socket.socket(family, socket.SOCK_DGRAM)
            listener.bind((address, port))
            monitor.register(listener, selectors.EVENT_READ)
    pathlib.Path(sys.argv[1]).touch()
    for _ in range(6):
        [entry, *_] = monitor.select(4)
        listener = entry[0].fileobj
        payload, client = listener.recvfrom(256)
        listener.sendto(payload, client)
PY
server=$!
for _ in 1 2 3 4 5 6 7 8 9 10; do
    [ ! -e "$WORK/server" ] || break
    sleep 0.05
done
test -e "$WORK/server"

python3 - <<'PY'
import socket

for family, address in [(socket.AF_INET, "192.0.2.2"), (socket.AF_INET6, "2001:db8::2")]:
    for port, mark in [(853, 0), (854, 0), (853, 47)]:
        with socket.socket(family, socket.SOCK_DGRAM) as client:
            client.settimeout(2)
            if mark:
                client.setsockopt(socket.SOL_SOCKET, socket.SO_MARK, mark)
            client.connect((address, port))
            client.send(b"route-check")
            assert client.recv(256) == b"route-check"
PY
wait "$server"

packets() {
    if [ "$FW_BACKEND" = nft ]; then
        case "$1" in out) chain=out ;; in) chain=input ;; esac
        nft list chain inet r2o "$chain" |
            awk -v set="@dns_route$2" '$0 ~ set {for(i=1;i<NF-1;i++) if($i=="counter" && $(i+1)=="packets"){print $(i+2); exit}}'
    else
        case "$2" in 4) fw=iptables ;; 6) fw=ip6tables ;; esac
        case "$1" in out) chain=R2O_DNS_OUT ;; in) chain=R2O_DNS_IN ;; esac
        "$fw" -t mangle -n -v -x -L "$chain" | awk '$3=="NFQUEUE" {print $1}'
    fi
}
has_route() {
    if [ "$FW_BACKEND" = nft ]; then
        nft get element inet r2o "dns_route$1" "{ $2 . $3 . 853 }" >/dev/null 2>&1
    else
        ipset -quiet test "r2o_dns_route$1" "$2,$3:853"
    fi
}
for family in 4 6; do
    [ "$(packets out "$family")" = 1 ]
    [ "$(packets in "$family")" = 2 ]
done
sh "$FIREWALL" dns-route del 192.0.2.2 udp 853 0
sh "$FIREWALL" dns-route del 192.0.2.2 udp 853 0
if has_route 4 192.0.2.2 udp; then exit 1; fi
has_route 6 2001:db8::2 udp
sh "$FIREWALL" dns-route add 192.0.2.2 tcp 853 1
has_route 4 192.0.2.2 tcp
sleep 1.2
if has_route 4 192.0.2.2 tcp; then exit 1; fi
sh "$FIREWALL" down
if has_route 6 2001:db8::2 udp; then exit 1; fi
echo "ПРОЙДЕНО ($FW_BACKEND): адресные DNS-маршруты IPv4/IPv6, исключение прямой пробы и снятие записи"
