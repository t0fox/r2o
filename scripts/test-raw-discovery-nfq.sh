#!/bin/sh
set -eu

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
ip link add r0c netns "$ROUTER" type veth peer name c0 netns "$CLIENT"
ip link add r0s netns "$ROUTER" type veth peer name s0 netns "$SERVER"
ip -n "$ROUTER" addr add 203.0.113.1/24 dev r0c
ip -n "$ROUTER" addr add 198.51.100.1/24 dev r0s
ip -n "$CLIENT" addr add 203.0.113.2/24 dev c0
ip -n "$SERVER" addr add 198.51.100.2/24 dev s0
ip -n "$ROUTER" link set r0c up
ip -n "$ROUTER" link set r0s up
ip -n "$CLIENT" link set c0 up
ip -n "$SERVER" link set s0 up
ip -n "$CLIENT" route add default via 203.0.113.1
ip -n "$SERVER" route add default via 198.51.100.1
ip -n "$ROUTER" route add default via 198.51.100.2
ip netns exec "$ROUTER" sysctl -qw net.ipv4.ip_forward=1
# Keep a real propagation interval between the send and the peer's ACK.
ip netns exec "$ROUTER" tc qdisc add dev r0s root netem delay 20ms

# OpenWrt's production hook pair for forwarded TCP and the raw socket mark.
ip netns exec "$ROUTER" nft -f - <<EOF
table ip r2o_raw_test {
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
table ip r2o_raw_peer {
    chain incoming {
        type filter hook input priority filter; policy accept;
        tcp dport $PORT ip length > 220 counter drop
        tcp dport $PORT ip length > 130 counter accept
    }
}
EOF

ip netns exec "$SERVER" python3 -u - "$PORT" >"$WORK/server.log" 2>&1 <<'PY' &
import socket
import sys

payload = b'\x01' + bytes(range(255))
with socket.socket() as server:
    server.bind(('198.51.100.2', int(sys.argv[1])))
    server.listen()
    server.settimeout(15)
    print('ready')
    for _ in range(2):
        client, _ = server.accept()
        with client:
            client.settimeout(8)
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

ip netns exec "$ROUTER" env R2O_RAW_DISCOVERY=1 "$R2OD_BIN" --mode apply --queue "$QUEUE" \
    --family ipv4 --controller-only --mark "$MARK" --probe-mark 291 \
    --control "$SOCKET_ROOT/datapath.sock" >"$WORK/datapath.log" 2>&1 &
DATAPATH_PID=$!
r2o_wait_nfq "$ROUTER" "$DATAPATH_PID" "$QUEUE" "$SOCKET_ROOT/datapath.sock" "$WORK/nfqueue.log"

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
for own in false true; do
    log="$WORK/controller-$own.log"
    ip netns exec "$ROUTER" env R2O_RAW_DISCOVERY=1 "$R2OC_BIN" --serve "$SOCKET_ROOT/datapath.sock" \
        "$WORK/catalog.json" --discover --mark 291 >"$log" 2>&1 &
    CONTROLLER_PID=$!
    await_log "$log" '^r2o-controller: запущен' "$CONTROLLER_PID"
    ip netns exec "$CLIENT" python3 - "$PORT" "$own" <<'PY'
import socket
import sys
import time

with socket.create_connection(('198.51.100.2', int(sys.argv[1])), timeout=6) as client:
    start = time.monotonic()
    client.sendall(b'\x01' + bytes(range(255)))
    expected = b'RAW TCP reply'
    assert client.makefile('rb').read(len(expected)) == expected
    print(f'RAW TCP: application exchange {time.monotonic() - start:.3f} s, own={sys.argv[2]}')
    time.sleep(0.1)
PY
    await_log "$log" "RAW 198\.51\.100\.2:$PORT measurement=[0-9]+: installed own=$own" "$CONTROLLER_PID"
    await_log "$log" "RAW 198\.51\.100\.2:$PORT measurement=[0-9]+ execution=[0-9]+: transport-ack saved" "$CONTROLLER_PID"
    # The normal clean-shutdown flush persists the dirty catalog. A fresh
    # controller must load the exact RAW profile from disk for the next flow.
    kill -TERM "$CONTROLLER_PID"
    wait "$CONTROLLER_PID"
    CONTROLLER_PID=
done
wait "$SERVER_PID"
SERVER_PID=
ip netns exec "$SERVER" nft list table ip r2o_raw_peer >"$WORK/peer-nft.log"
ip netns exec "$ROUTER" nft list table ip r2o_raw_test >"$WORK/router-nft.log"
awk '/drop$/   {for (i=1;i<NF;i++) if ($i=="packets" && $(i+1)>=4) good=1} END {exit !good}' "$WORK/peer-nft.log"
awk '/accept$/ {for (i=1;i<NF;i++) if ($i=="packets" && $(i+1)>=4) good=1} END {exit !good}' "$WORK/peer-nft.log"
python3 - "$WORK/catalog.json" "$PORT" <<'PY'
import hashlib
import json
import sys

with open(sys.argv[1]) as file:
    catalog = json.load(file)
bindings = [b for box in catalog['boxes'] for b in box['bindings'] if b['kind'] == 'raw']
assert len(bindings) == 1, bindings
binding = bindings[0]
expected = dict(target='198.51.100.2', transport=6, family=4, port=int(sys.argv[2]), verified_by=8)
assert all(binding[key] == value for key, value in expected.items()), binding
profile = bytes.fromhex(binding['raw_profile'])
assert profile[:2] == b'\x01\x00' and profile[2] == binding['tcp_profile']
assert profile[3:] == hashlib.sha256(b'\x01' + bytes(range(255))).digest()
print('RAW TCP: exact endpoint and profile persisted with transport ACK evidence')
PY
grep -hE 'RAW .*installed own=|transport-ack saved' "$WORK/controller-false.log" "$WORK/controller-true.log"
