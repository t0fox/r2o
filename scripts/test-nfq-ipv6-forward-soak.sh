#!/bin/sh
set -eu

SCRIPT_DIR=$(CDPATH='' cd -- "$(dirname "$0")" && pwd)
ROOT=$(CDPATH='' cd -- "$SCRIPT_DIR/.." && pwd)
TARGET_DIR=$(printenv CARGO_TARGET_DIR 2>/dev/null || printf '%s/target' "$ROOT")
R2OD_BIN=$(printenv R2OD_BIN 2>/dev/null || printf '%s/release/r2o-datapath' "$TARGET_DIR")
FLOW_COUNT=$(printenv R2O_IPV6_STRESS_FLOWS 2>/dev/null || printf '1024')
DURATION=$(printenv R2O_IPV6_STRESS_SECONDS 2>/dev/null || printf '300')
TEST_TMP=$(printenv R2O_TEST_TMP 2>/dev/null || printf '/mnt/e/r2o-tooling/tests')
QUEUE=62010
MARK=0x123
DATAPATH_MARK=119
UDP_PORT=4465
TCP_PORT=4466
CLIENT_IP=2001:db8:211::2
GATEWAY_CLIENT_IP=2001:db8:211::1
GATEWAY_SERVER_IP=2001:db8:212::1
SERVER_IP=2001:db8:212::2
CLIENT_NS=r2o-v6-soak-client-$$
GATEWAY_NS=r2o-v6-soak-gateway-$$
SERVER_NS=r2o-v6-soak-server-$$
CLIENT_IF=cv$$
GATEWAY_CLIENT_IF=gc$$
GATEWAY_SERVER_IF=gs$$
SERVER_IF=sv$$
WORK=
R2OD_PID=
SERVER_PID=
MONITOR_PID=

case "$FLOW_COUNT:$DURATION" in
    *[!0-9:]*|:*) echo 'R2O_IPV6_STRESS_FLOWS and R2O_IPV6_STRESS_SECONDS must be positive integers' >&2; exit 2 ;;
esac
if [ "$FLOW_COUNT" -lt 1 ] || [ "$FLOW_COUNT" -gt 1536 ] || [ "$DURATION" -lt 1 ]; then
    echo 'stress requires 1..1536 UDP flows and a positive duration' >&2
    exit 2
fi
case "$TEST_TMP" in /mnt/e/*) ;; *) echo 'R2O_TEST_TMP must stay on E:' >&2; exit 2 ;; esac
if [ "$(id -u)" -ne 0 ]; then
    echo 'run this Linux namespace test as root' >&2
    exit 1
fi
for tool in ip nft python3 awk sort grep cut xargs; do
    command -v "$tool" >/dev/null 2>&1 || { echo "missing required command: $tool" >&2; exit 1; }
done
[ -x "$R2OD_BIN" ] || { echo "R2O datapath binary is not executable: $R2OD_BIN" >&2; exit 1; }

mkdir -p "$TEST_TMP"
WORK=$(mktemp -d "$TEST_TMP/r2o-nfq-ipv6-soak.XXXXXX")
case "$WORK" in "$TEST_TMP"/r2o-nfq-ipv6-soak.*) ;; *) echo "unexpected temp path: $WORK" >&2; exit 2 ;; esac

cleanup() {
    status=$?
    for pid in "$MONITOR_PID" "$R2OD_PID" "$SERVER_PID"; do
        if [ -n "$pid" ]; then kill -TERM "$pid" 2>/dev/null || true; fi
    done
    for pid in "$MONITOR_PID" "$R2OD_PID" "$SERVER_PID"; do
        if [ -n "$pid" ]; then wait "$pid" 2>/dev/null || true; fi
    done
    for ns in "$CLIENT_NS" "$GATEWAY_NS" "$SERVER_NS"; do
        if ip netns list | awk '{print $1}' | grep -Fxq "$ns"; then
            ip netns pids "$ns" | xargs -r kill 2>/dev/null || true
            ip netns del "$ns" 2>/dev/null || true
        fi
    done
    if [ "$status" -ne 0 ] && [ -n "$WORK" ]; then
        for log in "$WORK"/*.log "$WORK"/*.out; do
            [ ! -f "$log" ] || { echo "--- $log ---" >&2; cat "$log" >&2; }
        done
    fi
    if [ -n "$WORK" ]; then rm -rf -- "$WORK"; fi
}
trap cleanup EXIT
trap 'exit 129' HUP
trap 'exit 130' INT
trap 'exit 143' TERM

cat >"$WORK/server.py" <<'PY'
import socket
import sys
import threading
import time

udp_port, tcp_port, ready_path, duration = int(sys.argv[1]), int(sys.argv[2]), sys.argv[3], int(sys.argv[4])
udp = socket.socket(socket.AF_INET6, socket.SOCK_DGRAM)
udp.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 8 * 1024 * 1024)
udp.bind(("2001:db8:212::2", udp_port))
udp.settimeout(0.25)
listener = socket.socket(socket.AF_INET6, socket.SOCK_STREAM)
listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
listener.settimeout(0.25)
listener.bind(("2001:db8:212::2", tcp_port))
listener.listen(4)
stopping = threading.Event()
peers = set()
udp_packets = 0
tcp_bytes = 0

def serve_tcp():
    global tcp_bytes
    while not stopping.is_set():
        try:
            connection, _ = listener.accept()
        except socket.timeout:
            continue
        except OSError:
            return
        with connection:
            connection.settimeout(1)
            while not stopping.is_set():
                try:
                    data = connection.recv(32768)
                except socket.timeout:
                    continue
                except OSError:
                    break
                if not data:
                    break
                tcp_bytes += len(data)
                connection.sendall(data)

threading.Thread(target=serve_tcp, daemon=True).start()
with open(ready_path, "w", encoding="ascii") as ready:
    ready.write("ready")
deadline = time.monotonic() + duration + 8
try:
    while not stopping.is_set() and time.monotonic() < deadline:
        try:
            data, peer = udp.recvfrom(1200)
        except socket.timeout:
            continue
        peers.add(peer[1])
        udp_packets += 1
        udp.sendto(data, peer)
finally:
    stopping.set()
    listener.close()
    udp.close()
    print(f"udp_unique_peers={len(peers)} udp_packets={udp_packets} tcp_bytes={tcp_bytes}", flush=True)
PY

cat >"$WORK/client.py" <<'PY'
import selectors
import socket
import struct
import sys
import threading
import time

flow_count, duration = int(sys.argv[1]), int(sys.argv[2])
server_ip, udp_port, tcp_port = sys.argv[3], int(sys.argv[4]), int(sys.argv[5])
selector = selectors.DefaultSelector()
sockets = []
sequences = [0] * flow_count
udp_replies = 0
tcp_echoes = 0
tcp_bytes = 0
stop_tcp = threading.Event()
tcp_error = []

for index in range(flow_count):
    sock = socket.socket(socket.AF_INET6, socket.SOCK_DGRAM)
    sock.setsockopt(socket.SOL_SOCKET, getattr(socket, "SO_MARK", 36), 0x123)
    sock.bind(("2001:db8:211::2", 0))
    sock.connect((server_ip, udp_port))
    sock.setblocking(False)
    selector.register(sock, selectors.EVENT_READ, index)
    sockets.append(sock)

def exchange(indices):
    global udp_replies
    pending = set(indices)
    for index in indices:
        sequences[index] += 1
        sockets[index].send(struct.pack("!II", index, sequences[index]))
    deadline = time.monotonic() + 8
    while pending:
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise SystemExit(f"UDP response timeout with {len(pending)} pending flows")
        events = selector.select(remaining)
        if not events:
            raise SystemExit(f"UDP response timeout with {len(pending)} pending flows")
        for key, _ in events:
            data = key.fileobj.recv(32)
            if len(data) != 8:
                raise SystemExit(f"invalid UDP echo length: {len(data)}")
            index, sequence = struct.unpack("!II", data)
            if index != key.data or index not in pending or sequence != sequences[index]:
                raise SystemExit(f"invalid UDP echo flow={index} seq={sequence}")
            pending.remove(index)
            udp_replies += 1

tcp = socket.socket(socket.AF_INET6, socket.SOCK_STREAM)
tcp.setsockopt(socket.SOL_SOCKET, getattr(socket, "SO_MARK", 36), 0x123)
tcp.settimeout(10)
tcp.connect((server_ip, tcp_port))
payload = bytes(range(256)) * 256

def tcp_load():
    global tcp_echoes, tcp_bytes
    try:
        while not stop_tcp.is_set():
            tcp.sendall(payload)
            received = bytearray()
            while len(received) < len(payload):
                chunk = tcp.recv(len(payload) - len(received))
                if not chunk:
                    raise SystemExit("TCP echo closed early")
                received.extend(chunk)
            if received != payload:
                raise SystemExit("TCP echo payload mismatch")
            tcp_echoes += 1
            tcp_bytes += len(received)
            stop_tcp.wait(0.25)
    except BaseException as error:
        if not stop_tcp.is_set():
            tcp_error.append(error)

worker = threading.Thread(target=tcp_load, daemon=True)
worker.start()
started = time.monotonic()
deadline = started + duration
rounds = 0
try:
    while time.monotonic() < deadline or rounds == 0:
        for start in range(0, flow_count, 64):
            exchange(list(range(start, min(start + 64, flow_count))))
        rounds += 1
        if time.monotonic() < deadline:
            time.sleep(0.8)
        if tcp_error:
            raise SystemExit(str(tcp_error[0]))
finally:
    stop_tcp.set()
    worker.join(timeout=10)
    tcp.close()
    for sock in sockets:
        selector.unregister(sock)
        sock.close()
    selector.close()
elapsed = time.monotonic() - started
print(f"udp_flows={flow_count} udp_replies={udp_replies} udp_rounds={rounds} tcp_echoes={tcp_echoes} tcp_bytes={tcp_bytes} duration_sec={elapsed:.1f}")
if worker.is_alive():
    raise SystemExit("TCP echo worker did not stop")
if tcp_error:
    raise SystemExit(str(tcp_error[0]))
if udp_replies < flow_count or tcp_echoes == 0 or elapsed < duration:
    raise SystemExit("IPv6 mixed-load soak did not meet its traffic or duration requirements")
PY

ip netns add "$CLIENT_NS"
ip netns add "$GATEWAY_NS"
ip netns add "$SERVER_NS"
for ns in "$CLIENT_NS" "$GATEWAY_NS" "$SERVER_NS"; do ip netns exec "$ns" ip link set lo up; done
ip link add "$CLIENT_IF" type veth peer name "$GATEWAY_CLIENT_IF"
ip link set "$CLIENT_IF" netns "$CLIENT_NS"
ip link set "$GATEWAY_CLIENT_IF" netns "$GATEWAY_NS"
ip link add "$GATEWAY_SERVER_IF" type veth peer name "$SERVER_IF"
ip link set "$GATEWAY_SERVER_IF" netns "$GATEWAY_NS"
ip link set "$SERVER_IF" netns "$SERVER_NS"
for spec in "$CLIENT_NS:$CLIENT_IF" "$GATEWAY_NS:$GATEWAY_CLIENT_IF" "$GATEWAY_NS:$GATEWAY_SERVER_IF" "$SERVER_NS:$SERVER_IF"; do
    ns=$(printf '%s' "$spec" | cut -d: -f1)
    iface=$(printf '%s' "$spec" | cut -d: -f2)
    ip netns exec "$ns" ip link set "$iface" mtu 1280 up
done
ip netns exec "$CLIENT_NS" ip -6 addr add "$CLIENT_IP"/64 dev "$CLIENT_IF" nodad
ip netns exec "$GATEWAY_NS" ip -6 addr add "$GATEWAY_CLIENT_IP"/64 dev "$GATEWAY_CLIENT_IF" nodad
ip netns exec "$GATEWAY_NS" ip -6 addr add "$GATEWAY_SERVER_IP"/64 dev "$GATEWAY_SERVER_IF" nodad
ip netns exec "$SERVER_NS" ip -6 addr add "$SERVER_IP"/64 dev "$SERVER_IF" nodad
ip netns exec "$GATEWAY_NS" sysctl -q -w net.ipv6.conf.all.forwarding=1
ip netns exec "$CLIENT_NS" ip -6 route add default via "$GATEWAY_CLIENT_IP" dev "$CLIENT_IF"
ip netns exec "$SERVER_NS" ip -6 route add default via "$GATEWAY_SERVER_IP" dev "$SERVER_IF"
ip netns exec "$CLIENT_NS" ip -6 route add default via "$GATEWAY_CLIENT_IP" dev "$CLIENT_IF" table 100
ip netns exec "$CLIENT_NS" ip -6 rule add priority 100 fwmark "$MARK"/0xffffffff table 100
route=$(ip netns exec "$CLIENT_NS" ip -6 route get "$SERVER_IP" from "$CLIENT_IP" mark "$MARK")
printf '%s\n' "$route" | grep -Fq "via $GATEWAY_CLIENT_IP" || { printf '%s\n' "$route" >&2; exit 1; }

ip netns exec "$GATEWAY_NS" nft add table inet r2o
ip netns exec "$GATEWAY_NS" nft 'add chain inet r2o forward { type filter hook forward priority 0; policy accept; }'
ip netns exec "$GATEWAY_NS" nft add rule inet r2o forward ip6 saddr "$CLIENT_IP" ip6 daddr "$SERVER_IP" udp dport "$UDP_PORT" meta mark != "$DATAPATH_MARK" counter queue num "$QUEUE"
ip netns exec "$GATEWAY_NS" nft add rule inet r2o forward ip6 saddr "$SERVER_IP" ip6 daddr "$CLIENT_IP" udp sport "$UDP_PORT" meta mark != "$DATAPATH_MARK" counter queue num "$QUEUE"
ip netns exec "$GATEWAY_NS" nft add rule inet r2o forward ip6 saddr "$CLIENT_IP" ip6 daddr "$SERVER_IP" tcp dport "$TCP_PORT" meta mark != "$DATAPATH_MARK" counter queue num "$QUEUE"
ip netns exec "$GATEWAY_NS" nft add rule inet r2o forward ip6 saddr "$SERVER_IP" ip6 daddr "$CLIENT_IP" tcp sport "$TCP_PORT" meta mark != "$DATAPATH_MARK" counter queue num "$QUEUE"
ip netns exec "$GATEWAY_NS" "$R2OD_BIN" --queue "$QUEUE" --family ipv6 --mode observe --r2o-flow-capacity 2048 --queue-len 4096 --mark "$DATAPATH_MARK" --stats 1 >"$WORK/datapath.log" 2>&1 &
R2OD_PID=$!
for _ in 1 2 3 4 5 6 7 8 9 10 11 12 13 14 15 16 17 18 19 20; do
    grep -Fq "r2o-datapath: очередь $QUEUE, IPv6" "$WORK/datapath.log" 2>/dev/null && break
    kill -0 "$R2OD_PID" 2>/dev/null || { cat "$WORK/datapath.log" >&2; exit 1; }
    sleep 0.05
done
grep -Fq "r2o-datapath: очередь $QUEUE, IPv6" "$WORK/datapath.log" || { cat "$WORK/datapath.log" >&2; exit 1; }
(
    while kill -0 "$R2OD_PID" 2>/dev/null; do
        awk '/^VmHWM:/ { print $2 }' "/proc/$R2OD_PID/status" 2>/dev/null || true
        sleep 0.2
    done
) >"$WORK/vmhwm.kib" &
MONITOR_PID=$!
ip netns exec "$SERVER_NS" python3 "$WORK/server.py" "$UDP_PORT" "$TCP_PORT" "$WORK/server.ready" "$DURATION" >"$WORK/server.log" 2>&1 &
SERVER_PID=$!
for _ in 1 2 3 4 5 6 7 8 9 10 11 12 13 14 15 16 17 18 19 20; do
    [ -f "$WORK/server.ready" ] && break
    kill -0 "$SERVER_PID" 2>/dev/null || { cat "$WORK/server.log" >&2; exit 1; }
    sleep 0.05
done
[ -f "$WORK/server.ready" ] || { echo 'IPv6 echo server did not start' >&2; exit 1; }
ip netns exec "$CLIENT_NS" python3 "$WORK/client.py" "$FLOW_COUNT" "$DURATION" "$SERVER_IP" "$UDP_PORT" "$TCP_PORT" >"$WORK/client.out"
wait "$SERVER_PID"
SERVER_PID=
kill -TERM "$R2OD_PID"
wait "$R2OD_PID"
R2OD_PID=
kill "$MONITOR_PID" 2>/dev/null || true
wait "$MONITOR_PID" 2>/dev/null || true
MONITOR_PID=

grep -Fq "udp_unique_peers=$FLOW_COUNT" "$WORK/server.log"
grep -Fq "udp_flows=$FLOW_COUNT" "$WORK/client.out"
grep -Eq 'tcp_echoes=[1-9][0-9]*' "$WORK/client.out"
nft_output=$(ip netns exec "$GATEWAY_NS" nft list chain inet r2o forward)
printf '%s\n' "$nft_output" | grep -Eq "udp dport $UDP_PORT .*counter packets [1-9][0-9]*"
printf '%s\n' "$nft_output" | grep -Eq "udp sport $UDP_PORT .*counter packets [1-9][0-9]*"
printf '%s\n' "$nft_output" | grep -Eq "tcp dport $TCP_PORT .*counter packets [1-9][0-9]*"
printf '%s\n' "$nft_output" | grep -Eq "tcp sport $TCP_PORT .*counter packets [1-9][0-9]*"
grep -Fq 'потеряно ядром 0' "$WORK/datapath.log"
peak_rss=$(sort -n "$WORK/vmhwm.kib" | tail -n 1)
[ -n "$peak_rss" ] || { echo 'datapath peak RSS was not sampled' >&2; exit 1; }
cat "$WORK/client.out" "$WORK/server.log"
printf 'ipv6_datapath_peak_rss_kib=%s\n' "$peak_rss"
grep -E 'TCP.*UDP|TCP-потоки' "$WORK/datapath.log" | tail -n 1
printf 'PASS: IPv6 gateway NFQUEUE soak, %s UDP flows plus concurrent 64-KiB TCP echo, %ss requested\n' "$FLOW_COUNT" "$DURATION"
