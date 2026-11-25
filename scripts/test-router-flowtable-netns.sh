#!/bin/sh
# fw4 передаёт потоки в netfilter на время работы R2O и восстанавливает
# нативный допуск при остановке.
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
CLIENT=
cleanup() {
    if [ -n "$SERVER" ]; then kill "$SERVER" 2>/dev/null || :; wait "$SERVER" 2>/dev/null || :; fi
    if [ -n "$CLIENT" ]; then kill "$CLIENT" 2>/dev/null || :; wait "$CLIENT" 2>/dev/null || :; fi
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
modprobe nft_tproxy
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
ip addr add 203.0.113.254/24 dev rlan
ip addr add 198.18.0.1/24 dev rwan
ip link set lo up
ip -6 addr add 2001:db8:1::1/64 dev rlan nodad
ip -6 addr add 2001:db8:2::1/64 dev rwan nodad
ip link set rlan up
ip link set rwan up
ip -n "$LAN" addr add 203.0.113.2/24 dev client
ip -n "$WAN" addr add 198.18.0.2/24 dev origin
ip -n "$LAN" -6 addr add 2001:db8:1::2/64 dev client nodad
ip -n "$WAN" -6 addr add 2001:db8:2::2/64 dev origin nodad
ip -n "$LAN" link set client up
ip -n "$WAN" link set origin up
ip -n "$LAN" route add default via 203.0.113.254
ip -n "$WAN" route add default via 198.18.0.1
ip -n "$LAN" -6 route add default via 2001:db8:1::1
ip -n "$WAN" -6 route add default via 2001:db8:2::1
ip route add default via 198.18.0.2
ip -6 route add default via 2001:db8:2::2
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
nft -s -n list flowtable inet fw4 ft >"$TEMP/native-flowtable"
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
    if [ -S "$TEMP/control4" ] && [ -S "$TEMP/control6" ] &&
        awk '$1 == 34000 || $1 == 34001 { if ($4 == 2) bound++ }
             END { exit bound != 2 }' /proc/net/netfilter/nfnetlink_queue; then
        break
    fi
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
import time

role, address, proto, port, ready = sys.argv[1:]
addr = (address, int(port))
tcp = proto == "tcp"
family = socket.AF_INET6 if ":" in address else socket.AF_INET
data = b"abcdef0123456789" * 16
bulk = data * 16384
with socket.socket(family, socket.SOCK_STREAM if tcp else socket.SOCK_DGRAM) as sock:
    sock.settimeout(8)
    if role.startswith("server"):
        if tcp:
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        if role == "server-transparent":
            sock.setsockopt(socket.SOL_IP, 19, 1)  # IP_TRANSPARENT
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
            for index in range(64):
                if role == "client-switch" and index == 32:
                    pathlib.Path(ready + ".switch").touch()
                    deadline = time.monotonic() + 8
                    while not pathlib.Path(ready + ".continue").exists():
                        assert time.monotonic() < deadline
                        time.sleep(0.05)
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
        /packets/ {print name, $0; ok = ($field >= min && $field < max)}
        END {exit !ok}
    '
}

seq4() { awk '$1 == 34000 { print $8 }' /proc/net/netfilter/nfnetlink_queue; }

transfer 198.18.0.2 tcp 443
transfer 2001:db8:2::2 tcp 443
transfer 198.18.0.2 udp 443
transfer 2001:db8:2::2 udp 443
transfer 198.18.0.2 tcp 853
# Проверяем поздний трафик в netfilter, отдельно от начального окна NFQUEUE.
counter tcp4 4194304 6291456 4
counter tcp6 4194304 6291456 4
counter udp4 64 65 2
counter udp6 64 65 2
counter other 4194304 6291456 4
nft -s -n list flowtable inet fw4 ft | cmp "$TEMP/native-flowtable" -
awk '
    $1 == 34000 || $1 == 34001 { if ($6 == 0 && $7 == 0 && $8 >= 8) ok++ }
    END { exit ok != 2 }
' /proc/net/netfilter/nfnetlink_queue

# Пересборка fw4 снимает защиту даже при исправном NFQUEUE. Событие возвращает её.
fw4_reload
if platform status; then exit 1; fi
# A foreign reference to ft must make the entire suspension fail atomically.
nft add chain inet fw4 foreign_flow
nft add rule inet fw4 foreign_flow tcp dport 8443 flow add @ft
platform event
for _ in $(seq 1 40); do
    [ ! -s "$R2O_RUN_DIR/platform.offload-error" ] || break
    sleep 0.1
done
test -s "$R2O_RUN_DIR/platform.offload-error"
nft list chain inet fw4 forward | grep -Eq 'flow (add|offload) @ft'
nft list chain inet fw4 foreign_flow | grep -Eq 'flow (add|offload) @ft'
nft delete chain inet fw4 foreign_flow
platform event
for _ in $(seq 1 40); do
    if platform status >"$TEMP/status" 2>/dev/null; then break; fi
    sleep 0.1
done
grep -q '^fw4_admission=suspended$' "$TEMP/status"
nft -a list chain inet fw4 r2o_offload >"$TEMP/chain"
platform up
nft -a list chain inet fw4 r2o_offload | cmp "$TEMP/chain" -

# The prefix alone is not evidence of proxy ownership. The same LAN
# destination was forwarded above. Here the masked RPDB rule delivers it
# to a foreign transparent listener instead of WAN.
ip route add local 0.0.0.0/0 dev lo table 105
ip rule add pref 105 fwmark 0x100000/0x100000 lookup 105
nft -f - <<'RULES'
table inet proxy_fixture {
    chain mark_lan {
        type filter hook prerouting priority mangle; policy accept;
        iifname "rlan" ip daddr 198.18.0.0/15 tcp dport 443 meta mark set 0x100000
    }
    chain redirect_lan {
        type filter hook prerouting priority dstnat; policy accept;
        meta mark & 0x100000 == 0x100000 tcp dport 443 tproxy ip to 127.0.0.1:1602 counter
    }
}
RULES
ip route get 198.18.0.2 from 203.0.113.2 iif rlan mark 0x100000 | grep -q '^local '
rm -f "$TEMP/ready"
python3 "$TEMP/traffic.py" server-transparent 127.0.0.1 tcp 1602 "$TEMP/ready" &
SERVER=$!
for _ in $(seq 1 40); do [ ! -f "$TEMP/ready" ] || break; sleep 0.1; done
before=$(seq4)
ip netns exec "$LAN" python3 "$TEMP/traffic.py" client 198.18.0.2 tcp 443 "$TEMP/ready"
wait "$SERVER"
SERVER=
[ "$(seq4)" = "$before" ]
nft list chain inet proxy_fixture redirect_lan | grep -Eq 'counter packets [1-9][0-9]*'
nft delete table inet proxy_fixture
ip rule del pref 105
ip route del local 0.0.0.0/0 dev lo table 105
echo 'TPROXY_LOCAL_DELIVERY_PASS'

# DNS hijacking is a separate DNAT path. The LAN query and the reply must
# stay with the router resolver, including replies reverse-translated to WAN IP.
nft -f - <<'RULES'
table inet dns_fixture {
    chain redirect_lan {
        type nat hook prerouting priority dstnat + 5; policy accept;
        iifname "rlan" udp dport 53 counter redirect to :53
    }
}
RULES
rm -f "$TEMP/ready"
python3 "$TEMP/traffic.py" server 203.0.113.254 udp 53 "$TEMP/ready" &
SERVER=$!
for _ in $(seq 1 40); do [ ! -f "$TEMP/ready" ] || break; sleep 0.1; done
before=$(seq4)
ip netns exec "$LAN" python3 "$TEMP/traffic.py" client 198.18.0.2 udp 53 "$TEMP/ready"
wait "$SERVER"
SERVER=
[ "$(seq4)" = "$before" ]
nft list chain inet dns_fixture redirect_lan | grep -Eq 'counter packets [1-9][0-9]*'
nft delete table inet dns_fixture
echo 'DNS_HIJACK_LOCAL_DELIVERY_PASS'

if [ "${R2O_TEST_FULLCONE:-0}" = 1 ]; then
    modprobe nft_fullcone
    nft -f - <<'RULES'
table ip fullcone_fixture {
    chain nat_wan {
        type nat hook postrouting priority srcnat; policy accept;
        oifname "rwan" udp dport 443 counter fullcone
    }
}
RULES
    before=$(seq4)
    transfer 198.18.0.2 udp 443
    [ "$(seq4)" -gt "$before" ]
    nft list chain ip fullcone_fixture nat_wan | grep -Eq 'counter packets [1-9][0-9]*'
    nft delete table ip fullcone_fixture
    echo 'FULLCONE_TRANSIT_PASS'
fi

# Accounting is attached when a conntrack entry is created. Create the old
# tuple while the platform is down so network events cannot re-enable accounting.
platform down
sysctl -qw net.netfilter.nf_conntrack_acct=0
ip netns exec "$WAN" python3 - "$TEMP" <<'PY' &
import pathlib, socket, sys
root = pathlib.Path(sys.argv[1])
with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as server:
    server.bind(("198.18.0.2", 443))
    server.settimeout(10)
    (root / "acct-server").touch()
    first = server.recvfrom(256)
    (root / "acct-old").touch()
    second = server.recvfrom(256)
    (root / "acct-second").touch()
    fresh = server.recvfrom(256)
    assert [first[0], second[0], fresh[0]] == [b"old", b"old", b"fresh"]
    assert first[1] == second[1] != fresh[1]
PY
SERVER=$!
for _ in $(seq 1 40); do [ ! -f "$TEMP/acct-server" ] || break; sleep 0.1; done
ip netns exec "$LAN" python3 - "$TEMP" <<'PY' &
import pathlib, socket, sys, time
root = pathlib.Path(sys.argv[1])

def await_signal(name):
    end = time.monotonic() + 8
    while not (root / name).exists():
        assert time.monotonic() < end, name
        time.sleep(.05)

with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as old:
    old.connect(("198.18.0.2", 443))
    old.send(b"old")
    await_signal("acct-recovered")
    old.send(b"old")
    await_signal("acct-fresh")
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as fresh:
        fresh.sendto(b"fresh", ("198.18.0.2", 443))
PY
CLIENT=$!
for _ in $(seq 1 40); do [ ! -f "$TEMP/acct-old" ] || break; sleep 0.1; done
test -f "$TEMP/acct-old"
[ "$(cat /proc/sys/net/netfilter/nf_conntrack_acct)" = 0 ]
platform up
before=$(seq4)
platform status >"$TEMP/status"
grep -q 'conntrack_accounting=enabled' "$TEMP/status"
if [ -r /proc/net/nf_conntrack ]; then
    grep -Eq '^conntrack_entries=sampled .*without_full_counters=[1-9]' "$TEMP/status"
fi
touch "$TEMP/acct-recovered"
for _ in $(seq 1 40); do [ ! -f "$TEMP/acct-second" ] || break; sleep 0.1; done
test -f "$TEMP/acct-second"
[ "$(seq4)" = "$before" ]
touch "$TEMP/acct-fresh"
wait "$CLIENT"
CLIENT=
wait "$SERVER"
SERVER=
[ "$(seq4)" -gt "$before" ]

# The running worker also restores a sysctl reset without replacing conntrack.
sysctl -qw net.netfilter.nf_conntrack_acct=0
platform event
for _ in $(seq 1 40); do
    if platform status >"$TEMP/status" 2>/dev/null; then break; fi
    sleep 0.1
done
grep -q 'conntrack_accounting=enabled' "$TEMP/status"
echo 'CONNTRACK_EXISTING_AND_FRESH_PASS'

if [ -n "${R2O_HTTP3_LAN_BIN:-}" ]; then
    http3() {
        R2O_H3_LAN="$LAN" R2O_H3_WAN="$WAN" R2O_H3_ORIGIN="$1" \
            R2O_H3_CONTROL="$TEMP/control$2" R2O_H3_EXPECT_APPLIED="$3" \
            R2O_H3_INSTALL_PLAN="${4:-$3}" R2O_H3_ORIGIN_FAIL="${5:-0}" \
            "$R2O_HTTP3_LAN_BIN" --exact r2o_http3_lan --ignored --nocapture || {
                cat "$TEMP"/datapath*.log >&2
                return 1
            }
    }
    http3 198.18.0.2:443 4 0
    http3 '[2001:db8:2::2]:443' 6 0

    # Одинаковые назначение, fwmark и oif скрывают различие шлюзов.
    ip -n "$WAN" addr add 198.18.0.3/24 dev origin
    ip route add 198.18.0.2/32 via 198.18.0.3 dev rwan onlink table 100
    ip rule add priority 100 iif rlan lookup 100
    ip route get 198.18.0.2 mark "$MARK" | grep -Eq 'dev rwan( |$)'
    ip route get 198.18.0.2 from 203.0.113.2 iif rlan mark "$MARK" | grep -Eq 'via 198\.18\.0\.3 dev rwan( |$)'
    sleep 1
    # План установлен, но при несовпадении RPDB остаётся только наблюдение.
    http3 198.18.0.2:443 4 0 1
    grep -q 'продолжаю наблюдение без применения плана' "$TEMP/datapath4.log"

    ip rule del priority 100
    sleep 1
    http3 198.18.0.2:443 4 1
    http3 '[2001:db8:2::2]:443' 6 1
    http3 198.18.0.2:443 4 1 1 1
fi

platform down
nft list chain inet fw4 forward | grep -Eq 'flow (add|offload) @ft'
nft -s -n list flowtable inet fw4 ft | cmp "$TEMP/native-flowtable" -
nft reset counter inet visibility tcp4 >/dev/null
transfer 198.18.0.2 tcp 443
counter tcp4 0 1048576 4

# A flow admitted before up keeps its tuple, but its second half must
# traverse netfilter after the native flowtable is recreated.
nft reset counter inet visibility udp4 >/dev/null
rm -f "$TEMP/ready"
ip netns exec "$WAN" python3 "$TEMP/traffic.py" server 198.18.0.2 udp 443 "$TEMP/ready" &
SERVER=$!
for _ in $(seq 1 40); do [ ! -f "$TEMP/ready" ] || break; sleep 0.1; done
ip netns exec "$LAN" python3 "$TEMP/traffic.py" client-switch 198.18.0.2 udp 443 "$TEMP/ready" &
CLIENT=$!
for _ in $(seq 1 40); do [ ! -f "$TEMP/ready.switch" ] || break; sleep 0.1; done
test -f "$TEMP/ready.switch"
counter udp4 0 24 2
platform up
nft reset counter inet visibility udp4 >/dev/null
touch "$TEMP/ready.continue"
wait "$CLIENT"
CLIENT=
wait "$SERVER"
SERVER=
counter udp4 32 33 2
platform down
echo 'FW4_SUSPEND_AND_RESTORE_PASS'
