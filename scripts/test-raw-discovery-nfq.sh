#!/bin/sh
set -eu

# Every case uses a fresh, isolated client, router and peer.
if [ "$#" -eq 0 ]; then
    for family in ipv4 ipv6; do
        for setting in default 0 1; do
            sh "$0" "$family" "$setting"
        done
    done
    sh "$0" ipv4 empty
    sh "$0" ipv4 invalid
    exit 0
fi
[ "$#" -eq 2 ] || exit 2
FAMILY=$1
SETTING=$2
case "$FAMILY" in
    ipv4)
        AF=4 NFT_FAMILY=ip LENGTH_MATCH='ip length'
        CLIENT_IP=203.0.113.2 SERVER_IP=198.51.100.2
        ROUTER_CLIENT=203.0.113.1 ROUTER_SERVER=198.51.100.1 PREFIX=24
        FORWARDING=net.ipv4.ip_forward
        ;;
    ipv6)
        AF=6 NFT_FAMILY=ip6 LENGTH_MATCH='ip6 length'
        CLIENT_IP=2001:db8:1::2 SERVER_IP=2001:db8:2::2
        ROUTER_CLIENT=2001:db8:1::1 ROUTER_SERVER=2001:db8:2::1 PREFIX=64
        FORWARDING=net.ipv6.conf.all.forwarding
        ;;
    *) exit 2 ;;
esac
case "$SETTING" in
    default) unset R2O_RAW_DISCOVERY ;;
    empty) export R2O_RAW_DISCOVERY='' ;;
    0|1|invalid) export R2O_RAW_DISCOVERY="$SETTING" ;;
    *) exit 2 ;;
esac
printf 'RAW NFQUEUE: %s setting=%s\n' "$FAMILY" "$SETTING"

SCRIPT_DIR=$(CDPATH='' cd -- "$(dirname -- "$0")" && pwd)
. "$SCRIPT_DIR/nfq-test-ready.sh"
ROOT=$(CDPATH='' cd -- "$SCRIPT_DIR/.." && pwd)
TARGET_DIR=${CARGO_TARGET_DIR:-"$ROOT/target"}
R2OD_BIN=${R2OD_BIN:-"$TARGET_DIR/release/r2o-datapath"}
R2OC_BIN=${R2OC_BIN:-"$TARGET_DIR/release/r2o-controller"}
WORK_ROOT=${R2O_TEST_WORK_ROOT:-"$TARGET_DIR/test-work"}
CLIENT=r2o-raw-client-$$
ROUTER=r2o-raw-router-$$
SERVER=r2o-raw-server-$$
QUEUE=65513
PORT=18888
MARK=21083
DATAPATH_PID=
CONTROLLER_PID=
SERVER_PID=

mkdir -p "$WORK_ROOT"
WORK=$(mktemp -d "$WORK_ROOT/raw-discovery.XXXXXX")
SOCKET_ROOT=$(mktemp -d /tmp/r2o-raw.XXXXXX)
printf '%s\n' '{"boxes":[]}' >"$WORK/catalog.json"

cleanup() {
    status=$?
    trap - EXIT HUP INT TERM
    for pid in "$CONTROLLER_PID" "$DATAPATH_PID" "$SERVER_PID"; do
        if [ -n "$pid" ] && kill -0 "$pid" 2>/dev/null; then
            kill -TERM "$pid"
            if wait "$pid"; then :; fi
        fi
    done
    for ns in "$SERVER" "$CLIENT" "$ROUTER"; do
        if [ -e "/run/netns/$ns" ]; then ip netns del "$ns"; fi
    done
    rm -rf "$SOCKET_ROOT"
    if [ "$status" -eq 0 ]; then
        rm -rf "$WORK"
    else
        echo "RAW NFQUEUE logs: $WORK" >&2
        for log in "$WORK"/*.log; do
            if [ -f "$log" ]; then tail -n 60 "$log" >&2; fi
        done
    fi
    exit "$status"
}
trap cleanup EXIT HUP INT TERM

for ns in "$ROUTER" "$CLIENT" "$SERVER"; do
    ip netns add "$ns"
    ip -n "$ns" link set lo up
done
ip link add r0c address 02:00:00:00:00:01 netns "$ROUTER" type veth \
    peer name c0 address 02:00:00:00:00:02 netns "$CLIENT"
ip link add r0s address 02:00:00:00:00:03 netns "$ROUTER" type veth \
    peer name s0 address 02:00:00:00:00:04 netns "$SERVER"
add_address() {
    if [ "$AF" = 6 ]; then
        ip -n "$1" -6 addr add "$2/$PREFIX" dev "$3" nodad
    else
        ip -n "$1" -4 addr add "$2/$PREFIX" dev "$3"
    fi
}
add_address "$ROUTER" "$ROUTER_CLIENT" r0c
add_address "$ROUTER" "$ROUTER_SERVER" r0s
add_address "$CLIENT" "$CLIENT_IP" c0
add_address "$SERVER" "$SERVER_IP" s0
ip -n "$ROUTER" link set r0c up
ip -n "$ROUTER" link set r0s up
ip -n "$CLIENT" link set c0 up
ip -n "$SERVER" link set s0 up
ip -n "$CLIENT" "-$AF" route add default via "$ROUTER_CLIENT" dev c0
ip -n "$SERVER" "-$AF" route add default via "$ROUTER_SERVER" dev s0
ip -n "$ROUTER" "-$AF" route add default via "$SERVER_IP" dev r0s
ip netns exec "$ROUTER" sysctl -qw "$FORWARDING=1"
if [ "$AF" = 6 ]; then
    # Resolve the fixed peers before TCP starts so IPv6 neighbor discovery
    # does not inflate the handshake RTT and the ensuing retransmission timers.
    ip -n "$CLIENT" -6 neigh add "$ROUTER_CLIENT" lladdr 02:00:00:00:00:01 nud permanent dev c0
    ip -n "$ROUTER" -6 neigh add "$CLIENT_IP" lladdr 02:00:00:00:00:02 nud permanent dev r0c
    ip -n "$SERVER" -6 neigh add "$ROUTER_SERVER" lladdr 02:00:00:00:00:03 nud permanent dev s0
    ip -n "$ROUTER" -6 neigh add "$SERVER_IP" lladdr 02:00:00:00:00:04 nud permanent dev r0s
fi
# Keep a real propagation interval between the send and the peer's ACK.
ip netns exec "$ROUTER" tc qdisc add dev r0s root netem delay 20ms

# OpenWrt's production hook pair for forwarded TCP and the raw socket mark.
ip netns exec "$ROUTER" nft -f - <<EOF
table $NFT_FAMILY r2o_raw_test {
    chain outgoing {
        type filter hook postrouting priority mangle; policy accept;
        oifname "r0s" tcp dport $PORT meta mark $MARK counter return
        oifname "r0s" tcp dport $PORT ct direction original counter queue num $QUEUE
    }
    chain incoming {
        type filter hook forward priority mangle; policy accept;
        iifname "r0s" tcp sport $PORT ct direction reply counter queue num $QUEUE
    }
}
EOF
# The real peer accepts smaller wire segments and drops the unsplit request.
ip netns exec "$SERVER" nft -f - <<EOF
table $NFT_FAMILY r2o_raw_peer {
    chain incoming {
        type filter hook input priority filter; policy accept;
        tcp dport $PORT $LENGTH_MATCH > 220 counter drop
        tcp dport $PORT $LENGTH_MATCH > 130 counter accept
    }
}
EOF

ip netns exec "$SERVER" python3 -u - "$AF" "$SERVER_IP" "$PORT" "$SETTING" >"$WORK/server.log" 2>&1 <<'PY' &
import socket
import sys

payload = b'\x01' + bytes(range(255))
af, host, port, setting = sys.argv[1:]
disabled = setting in ('0', 'invalid')
with socket.socket(socket.AF_INET6 if af == '6' else socket.AF_INET) as server:
    server.bind((host, int(port)))
    server.listen()
    server.settimeout(15)
    print('ready')
    for _ in range(1 if disabled else 2):
        client, _ = server.accept()
        with client:
            client.settimeout(6 if disabled else 8)
            if disabled:
                try:
                    data = client.recv(1)
                except TimeoutError:
                    data = b''
                assert not data, 'opt-out unexpectedly delivered the filtered request'
                continue
            client.setsockopt(socket.IPPROTO_TCP, socket.TCP_QUICKACK, 0)
            data = b''
            while len(data) < len(payload):
                chunk = client.recv(len(payload))
                assert chunk, 'incomplete RAW request'
                data += chunk
            assert data == payload, 'payload was altered by the datapath'
            client.sendall(b'RAW TCP reply')
            assert client.recv(1) == b'', 'unexpected client payload'
PY
SERVER_PID=$!

await_log() {
    log=$1
    expected=$2
    pid=$3
    attempt=0
    until grep -Eq "$expected" "$log"; do
        if ! kill -0 "$pid" 2>/dev/null || [ "$attempt" -ge 50 ]; then
            echo "Expected '$expected' in $log" >&2
            return 1
        fi
        sleep 0.1
        attempt=$((attempt + 1))
    done
}

await_log "$WORK/server.log" '^ready$' "$SERVER_PID"
if [ "$AF" = 6 ]; then
    endpoint="[$SERVER_IP]:$PORT"
else
    endpoint="$SERVER_IP:$PORT"
fi
endpoint_re=$(printf '%s\n' "$endpoint" | sed 's/\./\\./g; s/\[/\\[/g; s/\]/\\]/g')
rounds='false true'
requested=true
status_reason=ready
case "$SETTING" in
0|invalid)
    rounds=false
    requested=false
    status_reason=disabled-config
    [ "$SETTING" != invalid ] || status_reason=invalid-config
    ;;
esac
for own in $rounds; do
    dp_log="$WORK/datapath-$own.log"
    ip netns exec "$ROUTER" "$R2OD_BIN" --mode apply --queue "$QUEUE" \
        --family "$FAMILY" --controller-only --mark "$MARK" --probe-mark 291 \
        --control "$SOCKET_ROOT/datapath.sock" >"$dp_log" 2>&1 &
    DATAPATH_PID=$!
    r2o_wait_nfq "$ROUTER" "$DATAPATH_PID" "$QUEUE" "$SOCKET_ROOT/datapath.sock" "$WORK/nfqueue.log" "$AF"
    await_log "$dp_log" "RAW TCP requested=$requested ready=$requested reason=$status_reason" "$DATAPATH_PID"

    log="$WORK/controller-$own.log"
    ip netns exec "$ROUTER" "$R2OC_BIN" --serve "$SOCKET_ROOT/datapath.sock" \
        "$WORK/catalog.json" --discover --mark 291 >"$log" 2>&1 &
    CONTROLLER_PID=$!
    await_log "$log" '^r2o-controller: запущен' "$CONTROLLER_PID"
    await_log "$log" "RAW TCP requested=$requested ready=$requested reason=$status_reason" "$CONTROLLER_PID"
    ip netns exec "$CLIENT" python3 - "$SERVER_IP" "$PORT" "$SETTING" "$own" <<'PY_CLIENT'
import socket
import sys
import time

host, port, setting, own = sys.argv[1:]
with socket.create_connection((host, int(port)), timeout=6) as client:
    start = time.monotonic()
    client.sendall(b'\x01' + bytes(range(255)))
    expected = b'RAW TCP reply'
    if setting in ('0', 'invalid'):
        client.settimeout(4)
        try:
            data = client.recv(len(expected))
        except TimeoutError:
            data = b''
        assert not data, 'response unexpectedly received with RAW disabled'
        print('RAW TCP: opt-out left the filtered request unmodified')
    else:
        assert client.makefile('rb').read(len(expected)) == expected
        print(f'RAW TCP: application exchange {time.monotonic() - start:.3f} s, own={own}')
        time.sleep(0.1)
PY_CLIENT
    if [ "$requested" = true ]; then
        await_log "$log" "RAW $endpoint_re measurement=[0-9]+: installed own=$own" "$CONTROLLER_PID"
        await_log "$log" "RAW $endpoint_re measurement=[0-9]+ execution=[0-9]+: transport-ack saved" "$CONTROLLER_PID"
    fi
    # Flush the catalog and clear process state before verifying exact reuse.
    kill -TERM "$CONTROLLER_PID"
    wait "$CONTROLLER_PID"
    CONTROLLER_PID=
    kill -TERM "$DATAPATH_PID"
    wait "$DATAPATH_PID"
    DATAPATH_PID=
done
wait "$SERVER_PID"
SERVER_PID=
ip netns exec "$SERVER" nft list table "$NFT_FAMILY" r2o_raw_peer >"$WORK/peer-nft.log"
ip netns exec "$ROUTER" nft list table "$NFT_FAMILY" r2o_raw_test >"$WORK/router-nft.log"
if [ "$requested" = false ]; then
    awk '/drop$/ {for (i=1;i<NF;i++) if ($i=="packets" && $(i+1)>=2) good=1} END {exit !good}' "$WORK/peer-nft.log"
    awk '/accept$/ && /packets [1-9][0-9]* bytes/ {exit 1}' "$WORK/peer-nft.log"
    if grep -Eq 'installed own=|transport-ack saved' "$WORK/controller-false.log"; then exit 1; fi
else
    awk '/drop$/   {for (i=1;i<NF;i++) if ($i=="packets" && $(i+1)>=4) good=1} END {exit !good}' "$WORK/peer-nft.log"
    awk '/accept$/ {for (i=1;i<NF;i++) if ($i=="packets" && $(i+1)>=4) good=1} END {exit !good}' "$WORK/peer-nft.log"
    grep -hE 'installed own=|transport-ack saved' "$WORK/controller-false.log" "$WORK/controller-true.log"
fi
python3 - "$WORK/catalog.json" "$PORT" "$AF" "$SERVER_IP" "$SETTING" <<'PY'
import hashlib
import json
import sys

with open(sys.argv[1]) as file:
    catalog = json.load(file)
bindings = [b for box in catalog['boxes'] for b in box['bindings'] if b['kind'] == 'raw']
if sys.argv[5] in ('0', 'invalid'):
    assert not bindings, bindings
    print('RAW TCP: no binding persisted with opt-out')
    sys.exit(0)
assert len(bindings) == 1, bindings
binding = bindings[0]
expected = dict(target=sys.argv[4], transport=6, family=int(sys.argv[3]), port=int(sys.argv[2]), verified_by=8)
assert all(binding[key] == value for key, value in expected.items()), binding
profile = bytes.fromhex(binding['raw_profile'])
assert profile[:2] == b'\x01\x00' and profile[2] == binding['tcp_profile']
assert profile[3:] == hashlib.sha256(b'\x01' + bytes(range(255))).digest()
print('RAW TCP: exact endpoint and profile persisted with transport ACK evidence')
PY
