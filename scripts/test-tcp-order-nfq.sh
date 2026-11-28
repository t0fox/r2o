#!/bin/sh
set -eu

scripts=$(CDPATH='' cd -- "$(dirname -- "$0")" && pwd)
. "$scripts/nfq-test-ready.sh"
: "${R2OD_BIN:?path to r2o-datapath}"
: "${R2O_ORDER_TEST_BIN:?path to the compiled controller test binary}"
router=r2o-order-r-$$
peer=r2o-order-p-$$
queue=65514
port=18443
work=$(mktemp -d /tmp/r2o-order.XXXXXX)
dp=
server=

cleanup() {
    status=$?
    trap - EXIT HUP INT TERM
    for pid in "$dp" "$server"; do
        if [ -n "$pid" ] && kill -0 "$pid" 2>/dev/null; then
            kill -TERM "$pid"
            if wait "$pid"; then :; fi
        fi
    done
    for ns in "$peer" "$router"; do
        if [ -e "/run/netns/$ns" ]; then ip netns del "$ns"; fi
    done
    if [ "$status" -eq 0 ]; then
        rm -rf "$work"
    else
        for log in "$work"/*.log; do
            if [ -f "$log" ]; then tail -n 65 "$log" >&2; fi
        done
        echo "TCP order fixture logs: $work" >&2
    fi
    exit "$status"
}
trap cleanup EXIT HUP INT TERM

for ns in "$router" "$peer"; do
    ip netns add "$ns"
    ip -n "$ns" link set lo up
done
ip link add r0s netns "$router" type veth peer name s0 netns "$peer"
ip -n "$router" addr add 198.51.100.1/24 dev r0s
ip -n "$peer" addr add 198.51.100.2/24 dev s0
ip -n "$router" link set r0s up
ip -n "$peer" link set s0 up
ip -n "$router" route add default via 198.51.100.2
ip netns exec "$router" sysctl -qw net.ipv4.tcp_timestamps=1
ip netns exec "$router" nft -f - <<EOF
table ip r2o_order_test {
    chain outgoing {
        type filter hook postrouting priority mangle; policy accept;
        oifname "r0s" meta mark != 45 tcp dport $port counter queue num $queue
    }
    chain incoming {
        type filter hook input priority mangle; policy accept;
        iifname "r0s" tcp sport $port counter queue num $queue
    }
}
EOF
openssl req -x509 -newkey rsa:2048 -nodes -days 1 -subj /CN=order.example \
    -addext 'subjectAltName=DNS:order.example' -keyout "$work/key.pem" -out "$work/cert.pem" \
    >"$work/cert.log" 2>&1

run_phase() {
    ip netns exec "$router" env R2O_ORDER_TEST_PHASE="$1" R2O_ORDER_TEST_DIR="$work" \
        "$R2O_ORDER_TEST_BIN" --ignored --exact tcp_order_live::tcp_order_nfq_lifecycle --nocapture
}
run_phase prepare

# Observe TCP sequence ranges at the receiving interface before asking the
# kernel's ordinary TCP stack and Python SSL to do a full HTTPS exchange.
ip netns exec "$peer" python3 -u - "$port" "$work" >"$work/server.log" 2>&1 <<'PY' &
from pathlib import Path
import socket
import ssl
import struct
import sys

port, work = int(sys.argv[1]), Path(sys.argv[2])
cut, end = map(int, (work / 'ranges').read_text().split())
total = (work / 'hello').stat().st_size
context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
context.load_cert_chain(work / 'cert.pem', work / 'key.pem')
with socket.socket(socket.AF_PACKET, socket.SOCK_DGRAM, socket.htons(0x0800)) as trace, socket.socket() as listener:
    trace.bind(('s0', 0x0800))
    trace.settimeout(8)
    listener.bind(('198.51.100.2', port))
    listener.listen()
    listener.settimeout(8)
    print('ready')
    for expected, allow in [([0, cut], False), ([cut, 0], False), ([0, end, cut], True),
                            ([0, end, cut], True), ([0, cut], True)]:
        client, source = listener.accept()
        with client:
            base = None
            seen = []
            delivered = 0
            while delivered < total:
                packet = trace.recv(65535)
                if len(packet) < 40 or packet[9] != 6 or packet[16:20] != socket.inet_aton('198.51.100.2'):
                    continue
                ip_len = (packet[0] & 15) * 4
                sport, dport, seq = struct.unpack_from('!HHI', packet, ip_len)
                if (sport, dport) != (source[1], port):
                    continue
                tcp_len = (packet[ip_len + 12] >> 4) * 4
                flags = packet[ip_len + 13]
                if flags & 2:
                    base = (seq + 1) & 0xffffffff
                payload_size = len(packet) - ip_len - tcp_len
                if payload_size and base is not None:
                    seen.append((seq - base) & 0xffffffff)
                    delivered += payload_size
            assert delivered == total and seen == expected, (seen, expected, delivered, total)
            print(f'TCP ranges={seen}, HTTPS allowed={allow}')
            if not allow:
                client.setsockopt(socket.SOL_SOCKET, socket.SO_LINGER, struct.pack('ii', 1, 0))
                continue
            client.settimeout(5)
            with context.wrap_socket(client, server_side=True) as tls:
                request = tls.makefile('rb').readline()
                assert request.startswith(b'GET / '), request
                tls.sendall(b'HTTP/1.1 200 OK\r\nContent-Length: 9\r\nConnection: close\r\n\r\norder-ok\n')
PY
server=$!
attempt=0
until grep -q '^ready$' "$work/server.log"; do
    if ! kill -0 "$server" 2>/dev/null || [ "$attempt" -ge 50 ]; then exit 1; fi
    sleep 0.1
    attempt=$((attempt + 1))
done

start_datapath() {
    ip netns exec "$router" "$R2OD_BIN" --family ipv4 --mode apply --controller-only \
        --queue "$queue" --mark 45 --probe-mark 291 --control "$work/dp.sock" >"$work/dp-$1.log" 2>&1 &
    dp=$!
    r2o_wait_nfq "$router" "$dp" "$queue" "$work/dp.sock" "$work/nfq-$1.log"
}
stop_datapath() {
    kill -TERM "$dp"
    wait "$dp"
    dp=
}

start_datapath learn
run_phase learn
stop_datapath
start_datapath reuse
run_phase reuse
run_phase direct
wait "$server"
server=
cat "$work/server.log"
