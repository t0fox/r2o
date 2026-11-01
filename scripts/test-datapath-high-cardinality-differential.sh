#!/bin/sh
set -eu

repo_root=$(CDPATH='' cd -P "$(dirname "$0")/.." && pwd)
donor_root=${R2O_DONOR_ROOT:-"${repo_root%/*}/r2o-tooling/d2o-clean-main"}
tooling_root="${repo_root%/*}/r2o-tooling"
case "$donor_root" in /mnt/e/*) ;; *) echo 'D2O donor must stay on E:' >&2; exit 2 ;; esac
CARGO_HOME=${CARGO_HOME:-$tooling_root/linux-cargo}
RUSTUP_HOME=${RUSTUP_HOME:-$tooling_root/linux-rustup}
CARGO_TARGET_DIR=${CARGO_TARGET_DIR:-$tooling_root/linux-target}
TMPDIR=${TMPDIR:-$tooling_root/tests}
for path in "$tooling_root" "$CARGO_HOME" "$RUSTUP_HOME" "$CARGO_TARGET_DIR" "$TMPDIR"; do
    case "$path" in /mnt/e/*) ;; *) printf 'Build and temporary paths must stay on E: %s\n' "$path" >&2; exit 2 ;; esac
done
PATH="$CARGO_HOME/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"
export CARGO_HOME RUSTUP_HOME CARGO_TARGET_DIR TMPDIR PATH
cd "$repo_root"
expected_donor_sha=304ba893dd37197128ac8799c0495b035f6a38c0
actual_donor_sha=$(git -C "$donor_root" rev-parse HEAD)
if [ "$actual_donor_sha" != "$expected_donor_sha" ]; then
    printf 'Expected d2o %s, got %s\n' "$expected_donor_sha" "$actual_donor_sha" >&2
    exit 2
fi

flow_count=${R2O_STRESS_FLOWS:-1536}
duration=${R2O_STRESS_SECONDS:-60}
case "$flow_count:$duration" in
    *[!0-9:]*|:*) echo 'R2O_STRESS_FLOWS and R2O_STRESS_SECONDS must be positive integers' >&2; exit 2 ;;
esac
if [ "$flow_count" -lt 1 ] || [ "$flow_count" -gt 1536 ] || [ "$duration" -lt 1 ]; then
    echo 'stress requires 1..1536 UDP flows and a positive duration' >&2
    exit 2
fi

R2O_TEST_TMP=${R2O_TEST_TMP:-/mnt/e/r2o-tooling/tests}
case "$R2O_TEST_TMP" in /mnt/e/*) ;; *) echo 'R2O_TEST_TMP must stay on E:' >&2; exit 2 ;; esac
mkdir -p "$R2O_TEST_TMP"
work=$(mktemp -d "$R2O_TEST_TMP/r2o-datapath-high-cardinality.XXXXXX")
case "$work" in "$R2O_TEST_TMP"/r2o-datapath-high-cardinality.*) ;; *) echo "unexpected temp path: $work" >&2; exit 2 ;; esac

D2O_BIN=${D2OD_BIN:-"$donor_root/datapath/d2kd"}
TARGET_DIR=$CARGO_TARGET_DIR
R2O_BIN=${R2OD_BIN:-"$TARGET_DIR/release/r2o-datapath"}
make -s -C "$donor_root/datapath" d2kd CC="${CC:-cc}"
cargo build --release --locked --package r2o-datapath
for binary in "$D2O_BIN" "$R2O_BIN"; do
    case "$binary" in /mnt/e/*) ;; *) echo 'Production binaries must stay on E:' >&2; exit 2 ;; esac
done
if [ ! -x "$D2O_BIN" ] || [ ! -x "$R2O_BIN" ]; then
    echo 'C and Rust datapath binaries must be executable' >&2
    exit 2
fi
cat >"$work/server.py" <<'PY'
import selectors
import signal
import socket
import sys
import threading
import time

udp_port, tcp_port, ready_path, server_ip = int(sys.argv[1]), int(sys.argv[2]), sys.argv[3], sys.argv[4]
udp = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
udp.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 8 * 1024 * 1024)
udp.bind((server_ip, udp_port))
listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
listener.settimeout(0.2)
listener.bind((server_ip, tcp_port))
listener.listen(32)
stop = threading.Event()
peers = set()
udp_packets = 0
tcp_bytes = 0

def stop_server(_signum, _frame):
    stop.set()

signal.signal(signal.SIGTERM, stop_server)

def serve_tcp():
    global tcp_bytes
    connection = None
    while not stop.is_set():
        try:
            connection, _ = listener.accept()
            break
        except TimeoutError:
            continue
        except OSError:
            return
    if connection is None:
        return
    with connection:
        connection.settimeout(1)
        while not stop.is_set():
            try:
                data = connection.recv(16384)
            except TimeoutError:
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
last_packet = time.monotonic()
try:
    while not stop.is_set() and time.monotonic() - last_packet < 4:
        udp.settimeout(0.5)
        try:
            data, peer = udp.recvfrom(128)
        except TimeoutError:
            continue
        peers.add(peer[1])
        udp_packets += 1
        last_packet = time.monotonic()
        udp.sendto(data, peer)
finally:
    print(f"udp_unique_peers={len(peers)} udp_packets={udp_packets} tcp_bytes={tcp_bytes}", flush=True)
    listener.close()
    udp.close()
PY

cat >"$work/client.py" <<'PY'
import selectors
import socket
import struct
import sys
import threading
import time

flow_count, duration = int(sys.argv[1]), int(sys.argv[2])
client_ip, server_ip = sys.argv[3], sys.argv[4]
udp_port, tcp_port = int(sys.argv[5]), int(sys.argv[6])
selector = selectors.DefaultSelector()
sockets = []
sequences = [0] * flow_count
udp_replies = 0

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
            index, sequence = struct.unpack("!II", data)
            if index != key.data or index not in pending or sequence != sequences[index]:
                raise SystemExit(f"invalid UDP echo flow={index} seq={sequence}")
            pending.remove(index)
            udp_replies += 1

for index in range(flow_count):
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind((client_ip, 0))
    sock.connect((server_ip, udp_port))
    sock.setblocking(False)
    selector.register(sock, selectors.EVENT_READ, index)
    sockets.append(sock)
for start in range(0, flow_count, 64):
    exchange(list(range(start, min(start + 64, flow_count))))

tcp = socket.create_connection((server_ip, tcp_port), timeout=8)
tcp.settimeout(8)
payload = bytes(range(256)) * 256
tcp_echoes = 0
tcp_bytes = 0
stop_tcp = threading.Event()
tcp_error = []

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
            stop_tcp.wait(5)
    except BaseException as error:
        if not stop_tcp.is_set():
            tcp_error.append(error)

worker = threading.Thread(target=tcp_load, daemon=True)
worker.start()
started = time.monotonic()
deadline = started + duration
rounds = 0
while time.monotonic() < deadline:
    for start in range(0, flow_count, 64):
        exchange(list(range(start, min(start + 64, flow_count))))
    rounds += 1
    if tcp_error:
        raise SystemExit(str(tcp_error[0]))
    next_round = started + rounds
    delay = next_round - time.monotonic()
    if delay > 0:
        time.sleep(delay)

if rounds != duration:
    raise SystemExit(f"expected {duration} paced UDP rounds, completed {rounds}")

stop_tcp.set()
worker.join(timeout=10)
tcp.close()
for sock in sockets:
    selector.unregister(sock)
    sock.close()
selector.close()
elapsed = time.monotonic() - started
print(f"udp_flows={flow_count} udp_replies={udp_replies} udp_rounds={rounds} tcp_echoes={tcp_echoes} tcp_bytes={tcp_bytes} duration_sec={elapsed:.1f}")
if udp_replies < flow_count or tcp_echoes == 0:
    raise SystemExit("stress workload did not complete its required UDP and TCP traffic")
PY

client_ns=
server_ns=
daemon_pid=
server_pid=
monitor_pid=
cleanup() {
    status=$?
    if [ -n "$monitor_pid" ]; then kill "$monitor_pid" 2>/dev/null || true; wait "$monitor_pid" 2>/dev/null || true; fi
    if [ -n "$daemon_pid" ]; then kill -TERM "$daemon_pid" 2>/dev/null || true; wait "$daemon_pid" 2>/dev/null || true; fi
    if [ -n "$server_pid" ]; then kill -TERM "$server_pid" 2>/dev/null || true; wait "$server_pid" 2>/dev/null || true; fi
    for ns in "$client_ns" "$server_ns"; do
        if [ -n "$ns" ]; then
            ip netns pids "$ns" 2>/dev/null | xargs -r kill 2>/dev/null || true
            ip netns del "$ns" 2>/dev/null || true
        fi
    done
    if [ "$status" -ne 0 ]; then
        for log in "$work"/*.log "$work"/*.out; do [ ! -f "$log" ] || { echo "--- $log ---" >&2; cat "$log" >&2; }; done
    fi
    rm -rf -- "$work"
}
trap cleanup EXIT
trap 'exit 129' HUP
trap 'exit 130' INT
trap 'exit 143' TERM

run_case() {
    side=$1
    binary=$2
    queue=$3
    client_ns="r2o-hc-$$-$side-client"
    server_ns="r2o-hc-$$-$side-server"
    client_if="rhc$$"
    server_if="rhs$$"
    CLIENT_IP=198.51.100.1
    SERVER_IP=198.51.100.2
    UDP_PORT=4465
    TCP_PORT=4466
    ip netns add "$client_ns"
    ip netns add "$server_ns"
    ip link add "$client_if" type veth peer name "$server_if"
    ip link set "$client_if" netns "$client_ns"
    ip link set "$server_if" netns "$server_ns"
    ip netns exec "$client_ns" ip link set lo up
    ip netns exec "$server_ns" ip link set lo up
    ip netns exec "$client_ns" ip addr add "$CLIENT_IP/30" dev "$client_if"
    ip netns exec "$server_ns" ip addr add "$SERVER_IP/30" dev "$server_if"
    ip netns exec "$client_ns" ip link set "$client_if" up
    ip netns exec "$server_ns" ip link set "$server_if" up
    ip netns exec "$client_ns" ip route add default via "$SERVER_IP" dev "$client_if"
    ip netns exec "$client_ns" nft add table inet stress
    ip netns exec "$client_ns" nft 'add chain inet stress output { type filter hook output priority 0; policy accept; }'
    ip netns exec "$client_ns" nft 'add chain inet stress input { type filter hook input priority 0; policy accept; }'
    ip netns exec "$client_ns" nft add rule inet stress output oifname "$client_if" meta mark != 119 udp dport "$UDP_PORT" counter queue num "$queue"
    ip netns exec "$client_ns" nft add rule inet stress input iifname "$client_if" meta mark != 119 udp sport "$UDP_PORT" counter queue num "$queue"
    ip netns exec "$client_ns" nft add rule inet stress output oifname "$client_if" meta mark != 119 tcp dport "$TCP_PORT" counter queue num "$queue"
    ip netns exec "$client_ns" nft add rule inet stress input iifname "$client_if" meta mark != 119 tcp sport "$TCP_PORT" counter queue num "$queue"
    if [ "$side" = d2o ]; then
        ip netns exec "$client_ns" "$binary" --queue "$queue" --mode observe --flows 2048 --queue-len 4096 --mark 119 --stats 1 >"$work/$side.log" 2>&1 &
    else
        ip netns exec "$client_ns" "$binary" --queue "$queue" --family ipv4 --mode observe --r2o-flow-capacity 2048 --queue-len 4096 --mark 119 --stats 1 >"$work/$side.log" 2>&1 &
    fi
    daemon_pid=$!
    sleep 0.2
    kill -0 "$daemon_pid" 2>/dev/null || { cat "$work/$side.log" >&2; return 1; }
    (
        while kill -0 "$daemon_pid" 2>/dev/null; do
            awk '/^VmHWM:/ { print $2 }' "/proc/$daemon_pid/status" 2>/dev/null || true
            sleep 0.2
        done
    ) >"$work/$side.vm" &
    monitor_pid=$!
    ip netns exec "$server_ns" python3 "$work/server.py" "$UDP_PORT" "$TCP_PORT" "$work/$side.ready" "$SERVER_IP" >"$work/$side.server.log" 2>&1 &
    server_pid=$!
    attempts=0
    while [ ! -f "$work/$side.ready" ] && [ "$attempts" -lt 100 ]; do sleep 0.05; attempts=$((attempts + 1)); done
    [ -f "$work/$side.ready" ] || { echo "$side echo server did not start" >&2; return 1; }
    ip netns exec "$client_ns" python3 "$work/client.py" "$flow_count" "$duration" "$CLIENT_IP" "$SERVER_IP" "$UDP_PORT" "$TCP_PORT" >"$work/$side.client.out"
    ip netns exec "$client_ns" ip route show >"$work/$side.route.log"
    ip netns exec "$client_ns" ip route get "$SERVER_IP" >>"$work/$side.route.log"
    ip netns exec "$client_ns" nft list table inet stress >"$work/$side.nft.log"
    wait "$server_pid"
    server_pid=
    kill -TERM "$daemon_pid"
    wait "$daemon_pid"
    daemon_pid=
    kill "$monitor_pid" 2>/dev/null || true
    wait "$monitor_pid" 2>/dev/null || true
    monitor_pid=

    grep -Fq "udp_unique_peers=$flow_count" "$work/$side.server.log"
    grep -Fq "udp_flows=$flow_count" "$work/$side.client.out"
    grep -Fq "tcp_echoes=" "$work/$side.client.out"
    peak_rss=$(sort -n "$work/$side.vm" | tail -n 1)
    [ -n "$peak_rss" ] || { echo "$side peak RSS was not sampled" >&2; return 1; }
    if [ "$side" = d2o ]; then
        grep -Fq "потоков TCP 1 из 2048 (отказов 0), UDP $flow_count из 2048 (отказов 0)" "$work/$side.log"
    else
        grep -Fq "TCP-потоки 1 из 2048 (отказов 0), UDP-потоки $flow_count из 2048 (отказов 0)" "$work/$side.log"
    fi
    grep -Fq 'потеряно ядром 0' "$work/$side.log"
    cat "$work/$side.client.out" "$work/$side.server.log"
    printf '%s_peak_rss_kib=%s\n' "$side" "$peak_rss"
    grep -E 'TCP.*UDP|TCP-потоки' "$work/$side.log" | tail -n 1
    ip netns del "$client_ns"
    client_ns=
    ip netns del "$server_ns"
    server_ns=
}

run_case d2o "$D2O_BIN" 62000
run_case r2o "$R2O_BIN" 62001
printf 'D2O and R2O completed the same high-cardinality workload: UDP %s flows, one live TCP echo, %s seconds per side.\n' "$flow_count" "$duration"
