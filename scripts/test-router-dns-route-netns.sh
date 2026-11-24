#!/bin/sh
# Проверка маршрутов DNS в отдельном сетевом пространстве, без рабочих правил роутера.
set -eu

ROOT=$(CDPATH='' cd -- "$(dirname -- "$0")/.." && pwd)
if [ "${1:-}" != isolated ]; then
    exec unshare -n sh "$0" isolated
fi

WORK=$(mktemp -d)
peer=
queue_listener=
datapath4=
datapath6=
cleanup() {
    if [ -n "$peer" ]; then kill "$peer" 2>/dev/null || :; wait "$peer" 2>/dev/null || :; fi
    if [ -n "$queue_listener" ]; then
        kill "$queue_listener" 2>/dev/null || :
        wait "$queue_listener" 2>/dev/null || :
    fi
    for pid in "$datapath4" "$datapath6"; do
        [ -n "$pid" ] || continue
        kill "$pid" 2>/dev/null || :
        wait "$pid" 2>/dev/null || :
    done
    rm -rf -- "$WORK"
}
trap cleanup EXIT HUP INT TERM

export R2O_DIR="$WORK" R2O_CONFIG=/dev/null R2O_RUN_DIR="$WORK/run"
export FW_BACKEND=${FW_BACKEND:-nft} QUEUE_NUM=34000 QUEUE_NUM6=34001 MEASURE_MARK=47
export R2O_PPE_DEOFFLOAD=0 PORTS=853 DNS_PORTS=53
FIREWALL="$ROOT/router/r2o-firewall.sh"
export R2O_DATAPATH_BIN=${R2O_DATAPATH_BIN:-$ROOT/target/release/r2o-datapath}

ip link set lo up
modprobe nf_conntrack
modprobe nfnetlink_queue
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

python3 - "$WORK/queue" <<'PY' &
from collections import Counter
from pathlib import Path
import socket
import struct
import sys

with socket.socket(socket.AF_NETLINK, socket.SOCK_RAW, 12) as control:
    control.bind((0, 0))
    control.settimeout(6)

    def send(command, queue, attr, value, confirm=False):
        body = struct.pack("!BBH", 0, 0, queue)
        body += struct.pack("=HH", 4 + len(value), attr) + value
        body += bytes(-len(body) % 4)
        control.sendto(struct.pack("=IHHII", 16 + len(body), 0x300 | command,
                                   5 if confirm else 1, 1, 0) + body, (0, 0))
        if confirm:
            reply = control.recv(1024)
            assert struct.unpack_from("=i", reply, 16)[0] == 0

    for queue in (34000, 34001):
        send(2, queue, 1, struct.pack("!BBH", 1, 0, 0), confirm=True)
        send(2, queue, 2, struct.pack("!IB", 1600, 2), confirm=True)
    Path(sys.argv[1]).touch()
    hooks = Counter()
    for _ in range(6):
        packet = control.recv(4096)
        queue = struct.unpack_from("!H", packet, 18)[0]
        at = 20
        while at + 4 <= len(packet):
            length, kind = struct.unpack_from("=HH", packet, at)
            assert length >= 4
            if kind == 1:
                packet_id, _, hook = struct.unpack_from("!IHB", packet, at + 4)
                hooks[queue, hook] += 1
                send(1, queue, 2, struct.pack("!II", 1, packet_id))
                break
            at += (length + 3) & ~3
        else:
            raise AssertionError("В NFQUEUE отсутствует заголовок пакета")
    assert hooks == {(34000, 3): 1, (34000, 1): 2, (34001, 3): 1, (34001, 1): 2}, hooks
PY
queue_listener=$!
for _ in 1 2 3 4 5 6 7 8 9 10; do
    [ ! -e "$WORK/queue" ] || break
    sleep 0.05
done
test -e "$WORK/queue"

sh "$FIREWALL" up
sh "$FIREWALL" status
sh "$FIREWALL" dns-route add 192.0.2.2 udp 853 20
sh "$FIREWALL" dns-route add 2001:db8::2 udp 853 20
sh "$FIREWALL" dns-route add 2001:db8::2 udp 853 40
if sh "$FIREWALL" dns-route add 192.0.2.2 udp 53 20; then exit 1; fi
if sh "$FIREWALL" dns-route add ::1 tcp 853 20; then exit 1; fi

if [ "$FW_BACKEND" = nft ]; then
    nft list chain inet r2o dns_output | grep -Fq 'hook output'
else
    iptables -t mangle -C OUTPUT -j R2O_DNS_OUT
    ip6tables -t mangle -C OUTPUT -j R2O_DNS_OUT
fi

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
wait "$queue_listener"
queue_listener=

packets() {
    if [ "$FW_BACKEND" = nft ]; then
        case "$1" in out) chain=dns_output ;; in) chain=input ;; esac
        nft list chain inet r2o "$chain" |
            awk -v set="@${3:-dns_route}$2" '$0 ~ set {for(i=1;i<NF-1;i++) if($i=="counter" && $(i+1)=="packets"){print $(i+2); exit}}'
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
        if ipset -quiet list "r2o_dns_route$1" >/dev/null 2>&1; then
            ipset -quiet test "r2o_dns_route$1" "$2,$3:853"
        else
            ipset -quiet test "r2o_dn${1}_${3}_853" "$2"
        fi
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
if [ "$FW_BACKEND" = nft ]; then
    # Для регистрации маршрута с UID нужен текущий datapath с NFQA_CFG_F_UID_GID.
    R2O_PLATFORM_RUNTIME=1 "$R2O_DATAPATH_BIN" --queue "$QUEUE_NUM" --mode observe --r2o-flow-capacity 64 \
        > "$WORK/datapath4.log" 2>&1 &
    datapath4=$!
    R2O_PLATFORM_RUNTIME=1 "$R2O_DATAPATH_BIN" --queue "$QUEUE_NUM6" --family ipv6 --mode observe --r2o-flow-capacity 64 \
        > "$WORK/datapath6.log" 2>&1 &
    datapath6=$!
    uid4="$R2O_RUN_DIR/platform.uid.$QUEUE_NUM"
    uid6="$R2O_RUN_DIR/platform.uid.$QUEUE_NUM6"
    for _ in 1 2 3 4 5 6 7 8 9 10; do
        if [ -s "$uid4" ] && [ -s "$uid6" ]; then break; fi
        sleep 0.2
    done
    if [ ! -s "$uid4" ] || [ ! -s "$uid6" ]; then
        cat "$WORK/datapath4.log" "$WORK/datapath6.log" >&2
        exit 1
    fi
    sh "$FIREWALL" dns-route add 192.0.2.2 udp 854 20 411
    sh "$FIREWALL" dns-route add 2001:db8::2 udp 854 20 411
    if sh "$FIREWALL" dns-route add 192.0.2.2 udp 854 20 0; then exit 1; fi
    if sh "$FIREWALL" dns-route add 192.0.2.2 tcp 854 20 411; then exit 1; fi
    python3 - <<'PY'
import ctypes
import socket

libc = ctypes.CDLL(None)
for family, address in [(socket.AF_INET, "192.0.2.2"), (socket.AF_INET6, "2001:db8::2")]:
    for owner, mark in [(0, 0), (411, 47), (412, 0), (411, 0)]:
        original = libc.setfsuid(owner)
        try:
            assert libc.setfsuid(-1) == owner
            client = socket.socket(family, socket.SOCK_DGRAM)
        finally:
            libc.setfsuid(original)
        with client:
            if mark:
                client.setsockopt(socket.SOL_SOCKET, socket.SO_MARK, mark)
            client.sendto(b"owner-check", (address, 854))
PY
    for family in 4 6; do
        [ "$(packets out "$family" dns_h3_route)" = 1 ]
    done
    sh "$FIREWALL" dns-route del 192.0.2.2 udp 854 0 411
    if nft get element inet r2o dns_h3_route4 '{ 192.0.2.2 . 854 . 411 }' >/dev/null 2>&1; then exit 1; fi
    nft get element inet r2o dns_h3_route6 '{ 2001:db8::2 . 854 . 411 }' >/dev/null
else
    if sh "$FIREWALL" dns-route add 192.0.2.2 udp 854 20 411; then exit 1; fi
fi
sh "$FIREWALL" down
if has_route 6 2001:db8::2 udp; then exit 1; fi
echo "ПРОЙДЕНО ($FW_BACKEND): адресные DNS-маршруты IPv4/IPv6, исключение прямой пробы и снятие записи"
