#!/bin/sh
set -e

SCRIPT_DIR=$(CDPATH='' cd -P "$(dirname "$0")" && pwd)
ROOT=$(CDPATH='' cd -P "$SCRIPT_DIR/.." && pwd)
if [ -z "$R2O_TOOL_HOME" ]; then
    R2O_TOOL_HOME=$(dirname "$ROOT")/r2o-tooling
fi
D2O_ROOT=$R2O_DONOR_ROOT
if [ -z "$D2O_ROOT" ]; then
    D2O_ROOT=$R2O_TOOL_HOME/d2o-current-main
fi
if [ -z "$D2OD_BIN" ]; then
    D2OD_BIN=$D2O_ROOT/datapath/d2kd
fi
if [ -z "$R2OD_BIN" ]; then
    R2OD_BIN=$R2O_TOOL_HOME/linux-target/release/r2o-datapath
fi
TEMP_BASE=$R2O_TEST_TMP
if [ -z "$TEMP_BASE" ]; then
    TEMP_BASE=$R2O_TOOL_HOME/tests
fi
LOG=$R2O_TEST_LOG
if [ -z "$LOG" ]; then
    LOG=$R2O_TOOL_HOME/tests/r2o-nfq-ipv4-eio-differential-$(date +%F).log
fi
if [ -z "$CC" ]; then
    CC=cc
fi

EXPECTED_D2O_SHA=a63d9641f4e00aa35fa1e5ccbda47bb5f310c0fe
ACTUAL_D2O_SHA=$(git -c safe.directory="$D2O_ROOT" -C "$D2O_ROOT" rev-parse HEAD)
if [ "$ACTUAL_D2O_SHA" != "$EXPECTED_D2O_SHA" ]; then
    echo "D2O source must be $EXPECTED_D2O_SHA, got $ACTUAL_D2O_SHA" >&2
    exit 2
fi
for path in "$ROOT" "$R2O_TOOL_HOME" "$D2O_ROOT" "$D2OD_BIN" "$R2OD_BIN" "$TEMP_BASE" "$LOG"; do
    if [ -d /mnt/e ] && [ "$CI" != "true" ]; then
        case "$path" in
            /mnt/e/*) ;;
            *) echo "All WSL test files must stay on E: $path" >&2; exit 2 ;;
        esac
    fi
done
for tool in ip nft python3; do
    command -v "$tool" >/dev/null 2>&1 || {
        echo "required command is missing: $tool" >&2
        exit 1
    }
done
if [ "$(id -u)" -ne 0 ]; then
    echo "run as root to create isolated network namespaces" >&2
    exit 1
fi
[ -x "$D2OD_BIN" ] || { echo "D2O daemon is missing: $D2OD_BIN" >&2; exit 2; }
[ -x "$R2OD_BIN" ] || { echo "R2O daemon is missing: $R2OD_BIN" >&2; exit 2; }

mkdir -p "$TEMP_BASE" "$(dirname "$LOG")"
TEMP=$(mktemp -d "$TEMP_BASE/r2o-nfq-ipv4-eio.XXXXXX")
TMPDIR=$TEMP
export TMPDIR
SHIM=$TEMP/libnfq-recv-eio.so
QUEUE=64321
PORT=19001
CLIENT_NS=r2o-eio-client-$$
GATEWAY_NS=r2o-eio-gateway-$$
SERVER_NS=r2o-eio-server-$$
CLIENT_IF=ec$$
GATEWAY_IF=eg$$
GATEWAY_SERVER_IF=gs$$
SERVER_IF=es$$
DAEMON_PID=
SERVER_PID=
TCP_SERVER_PID=
D2O_NAT_QUEUE_COUNTS=
R2O_NAT_QUEUE_COUNTS=

cleanup() {
    STATUS=$?
    if [ -n "$DAEMON_PID" ]; then
        kill -TERM "$DAEMON_PID" 2>/dev/null || true
        wait "$DAEMON_PID" 2>/dev/null || true
    fi
    if [ -n "$SERVER_PID" ]; then
        kill -TERM "$SERVER_PID" 2>/dev/null || true
        wait "$SERVER_PID" 2>/dev/null || true
    fi
    if [ -n "$TCP_SERVER_PID" ]; then
        kill -TERM "$TCP_SERVER_PID" 2>/dev/null || true
        wait "$TCP_SERVER_PID" 2>/dev/null || true
    fi
    ip netns pids "$CLIENT_NS" 2>/dev/null | xargs -r kill -TERM 2>/dev/null || true
    ip netns pids "$GATEWAY_NS" 2>/dev/null | xargs -r kill -TERM 2>/dev/null || true
    ip netns pids "$SERVER_NS" 2>/dev/null | xargs -r kill -TERM 2>/dev/null || true
    ip netns del "$CLIENT_NS" 2>/dev/null || true
    ip netns del "$GATEWAY_NS" 2>/dev/null || true
    ip netns del "$SERVER_NS" 2>/dev/null || true
    if [ -d "$TEMP" ]; then
        if [ "$STATUS" -ne 0 ] || [ "$KEEP_TEST_WORK" = "1" ]; then
            echo "test files retained at $TEMP" >&2
        else
            case "$TEMP" in
                "$TEMP_BASE"/*) rm -rf -- "$TEMP" ;;
                *) echo "refusing to remove unexpected path: $TEMP" >&2 ;;
            esac
        fi
    fi
}
trap cleanup EXIT
trap 'exit 129' HUP
trap 'exit 130' INT
trap 'exit 143' TERM

"$CC" -std=c11 -O2 -Wall -Wextra -Werror -fPIC -shared \
    "$SCRIPT_DIR/nfq-recv-eio-preload.c" -ldl -o "$SHIM"

python3 - "$TEMP/empty.r2op" <<'PY'
import struct
import sys

record = struct.pack("!HHBB", 0x0002, 2, 6, 1)
header = b"R2OP" + struct.pack("!HHHH", 1, 0, 0, 1)
with open(sys.argv[1], "wb") as output:
    output.write(header + record)
PY
python3 - "$TEMP/tcp-hold.r2op" "$TEMP/tcp-hold.d2kp" <<'PY'
import struct
import sys

def tlv(kind, value):
    return struct.pack("!HH", kind, len(value)) + value

records = [
    tlv(0x0002, b"\x06\x01"),
    tlv(0x0100, b"\x00\x05\x00\x00"),
    tlv(0x0109, b"\x01"),
    tlv(0x010a, b""),
]
for magic, path in ((b"R2OP", sys.argv[1]), (b"D2KP", sys.argv[2])):
    header = magic + struct.pack("!HHHH", 1, 5, 0, len(records))
    with open(path, "wb") as output:
        output.write(header + b"".join(records))
PY
"$R2OD_BIN" --plan "$TEMP/empty.r2op" --mode observe --check >/dev/null
"$R2OD_BIN" --plan "$TEMP/tcp-hold.r2op" --mode apply --check >/dev/null

cat >"$TEMP/echo.py" <<'PY'
import socket
import sys

capture_path, port = sys.argv[1], int(sys.argv[2])
bind_host = sys.argv[3] if len(sys.argv) > 3 else "198.18.77.1"
expected_peer = sys.argv[4] if len(sys.argv) > 4 else None
sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
sock.bind((bind_host, port))
with open(capture_path, "w", encoding="ascii", buffering=1) as capture:
    while True:
        payload, peer = sock.recvfrom(2048)
        if expected_peer and peer[0] != expected_peer:
            raise RuntimeError(f"unexpected NAT source: {peer[0]}")
        if payload != b"ready":
            if expected_peer:
                capture.write(f"{peer[0]}:")
            capture.write(payload.decode("ascii") + chr(10))
        sock.sendto(payload, peer)
PY
cat >"$TEMP/client.py" <<'PY'
import socket
import sys
import time
from pathlib import Path

log_path, port = sys.argv[1], int(sys.argv[2])
fault = "FAULT-INJECTED recv(EIO) on NFQUEUE socket"
sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
sock.settimeout(0.2)
destination = ("198.18.77.1", port)

def exchange(payload):
    sock.sendto(payload, destination)
    reply, _ = sock.recvfrom(2048)
    if reply != payload:
        raise RuntimeError(f"echo mismatch: {reply!r} != {payload!r}")

for attempt in range(60):
    try:
        exchange(b"ready")
    except socket.timeout:
        time.sleep(0.025)
        continue
    try:
        log = Path(log_path).read_text(encoding="utf-8", errors="replace")
    except FileNotFoundError:
        log = ""
    if fault in log:
        break
    time.sleep(0.025)
else:
    raise RuntimeError("NFQUEUE recv(EIO) was not injected during warm-up")

for index in range(64):
    exchange(f"probe-{index:04d}".encode("ascii"))
print(f"warmups={attempt + 1} injected=1 echoed=64")
PY
cat >"$TEMP/tcp-hold-server.py" <<'PY'
import socket
import sys
import time
import os

first_path, capture_path, port = sys.argv[1], sys.argv[2], int(sys.argv[3])
first_tmp_path = first_path + ".tmp"
server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
server.bind(("198.18.78.2", port))
server.listen(1)
server.settimeout(3)
connection, _ = server.accept()
connection.settimeout(3)
received = bytearray()
while True:
    part = connection.recv(4096)
    if not part:
        break
    if not received:
        with open(first_tmp_path, "w", encoding="ascii") as first:
            first.write(f"{time.monotonic():.9f}\n")
        os.replace(first_tmp_path, first_path)
    received.extend(part)
with open(capture_path, "wb") as capture:
    capture.write(received)
connection.close()
server.close()
PY
cat >"$TEMP/tcp-hold-client.py" <<'PY'
import socket
import sys
import time
from pathlib import Path

log_path, trigger_path, first_path, capture_path = sys.argv[1:5]
udp_port, tcp_port, source_port = map(int, sys.argv[5:8])
fault = "FAULT-INJECTED recv(EIO) on NFQUEUE socket"
host = b"example.test"
sni_data = len(host + b"\x00\x00\x00").to_bytes(2, "big") + b"\x00" + len(host).to_bytes(2, "big") + host
sni = b"\x00\x00" + len(sni_data).to_bytes(2, "big") + sni_data
padding = b"\x00\x15" + (400).to_bytes(2, "big") + bytes(400)
extensions = sni + padding
body = (b"\x03\x03" + bytes(32) + b"\x00\x00\x02\x13\x01\x01\x00" +
        len(extensions).to_bytes(2, "big") + extensions)
handshake = b"\x01" + len(body).to_bytes(3, "big") + body
hello = b"\x16\x03\x03" + len(handshake).to_bytes(2, "big") + handshake

client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
client.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
client.settimeout(2)
client.bind(("198.18.77.2", source_port))
client.connect(("198.18.78.2", tcp_port))
started = time.monotonic()
client.sendall(hello[:40])
time.sleep(0.01)
if Path(first_path).exists():
    raise RuntimeError("held TCP payload reached the server before EIO")
Path(trigger_path).touch()

udp = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
udp.settimeout(1)
trigger = b"held-eio-trigger"
udp.sendto(trigger, ("198.18.77.1", udp_port))
reply, _ = udp.recvfrom(2048)
if reply != trigger:
    raise RuntimeError(f"trigger echo mismatch: {reply!r}")
deadline = time.monotonic() + 0.2
while not Path(first_path).exists() and time.monotonic() < deadline:
    time.sleep(0.001)
if not Path(first_path).exists():
    raise RuntimeError("held TCP packet was not released after NFQUEUE EIO")
first_at = float(Path(first_path).read_text(encoding="ascii"))
if first_at - started >= 0.09:
    raise RuntimeError(f"held TCP packet waited for timeout instead of EIO flush: {first_at - started:.3f}s")

client.sendall(hello[40:])
client.shutdown(socket.SHUT_WR)
deadline = time.monotonic() + 2
while not Path(capture_path).exists() and time.monotonic() < deadline:
    time.sleep(0.005)
if not Path(capture_path).exists():
    raise RuntimeError("server did not receive the complete TLS stream")
captured = Path(capture_path).read_bytes()
if captured != hello:
    raise RuntimeError(f"TLS stream mismatch: received {len(captured)} of {len(hello)} bytes")
log = Path(log_path).read_text(encoding="utf-8", errors="replace")
if fault not in log:
    raise RuntimeError("NFQUEUE recv(EIO) was not injected")
client.close()
udp.close()
print(f"held_tcp=1 eio=1 released={(first_at - started) * 1000:.1f}ms bytes={len(captured)}")
PY

ip netns add "$CLIENT_NS"
ip netns add "$GATEWAY_NS"
ip netns add "$SERVER_NS"
ip link add "$CLIENT_IF" type veth peer name "$GATEWAY_IF"
ip link set "$CLIENT_IF" netns "$CLIENT_NS"
ip link set "$GATEWAY_IF" netns "$GATEWAY_NS"
ip link add "$GATEWAY_SERVER_IF" type veth peer name "$SERVER_IF"
ip link set "$GATEWAY_SERVER_IF" netns "$GATEWAY_NS"
ip link set "$SERVER_IF" netns "$SERVER_NS"
ip -n "$CLIENT_NS" link set lo up
ip -n "$GATEWAY_NS" link set lo up
ip -n "$SERVER_NS" link set lo up
ip -n "$CLIENT_NS" addr add 198.18.77.2/24 dev "$CLIENT_IF"
ip -n "$GATEWAY_NS" addr add 198.18.77.1/24 dev "$GATEWAY_IF"
ip -n "$GATEWAY_NS" addr add 198.18.78.1/24 dev "$GATEWAY_SERVER_IF"
ip -n "$SERVER_NS" addr add 198.18.78.2/24 dev "$SERVER_IF"
ip -n "$CLIENT_NS" link set "$CLIENT_IF" up
ip -n "$GATEWAY_NS" link set "$GATEWAY_IF" up
ip -n "$GATEWAY_NS" link set "$GATEWAY_SERVER_IF" up
ip -n "$SERVER_NS" link set "$SERVER_IF" up
ip -n "$CLIENT_NS" route add 198.18.78.0/24 via 198.18.77.1
ip -n "$SERVER_NS" route add 198.18.77.0/24 via 198.18.78.1
ip netns exec "$GATEWAY_NS" sysctl -qw net.ipv4.ip_forward=1
ip netns exec "$GATEWAY_NS" nft add table inet eio
ip netns exec "$GATEWAY_NS" nft 'add chain inet eio input { type filter hook input priority 0; policy accept; }'
ip netns exec "$GATEWAY_NS" nft add rule inet eio input ip protocol udp udp dport "$PORT" queue num "$QUEUE" bypass
ip netns exec "$GATEWAY_NS" nft 'add chain inet eio forward { type filter hook forward priority 0; policy accept; }'
ip netns exec "$GATEWAY_NS" nft add rule inet eio forward ip saddr 198.18.77.2 ip daddr 198.18.78.2 tcp dport 4450 meta mark != 180001 queue num "$QUEUE" bypass
ip netns exec "$GATEWAY_NS" nft add rule inet eio forward ip saddr 198.18.78.2 ip daddr 198.18.77.2 tcp sport 4450 queue num "$QUEUE" bypass
ip netns exec "$GATEWAY_NS" nft add rule inet eio forward ip saddr 198.18.77.2 ip daddr 198.18.78.2 udp dport 19002 counter queue num "$QUEUE"
ip netns exec "$GATEWAY_NS" nft add rule inet eio forward ip saddr 198.18.78.2 ip daddr 198.18.77.2 udp sport 19002 counter queue num "$QUEUE"
ip netns exec "$GATEWAY_NS" nft add table ip eio_nat
ip netns exec "$GATEWAY_NS" nft 'add chain ip eio_nat postrouting { type nat hook postrouting priority srcnat; policy accept; }'
ip netns exec "$GATEWAY_NS" nft add rule ip eio_nat postrouting ip saddr 198.18.77.2 ip daddr 198.18.78.2 udp dport 19002 snat to 198.18.78.1
run_case() {
    CASE_NAME=$1
    CASE_LOG=$TEMP/$CASE_NAME.log
    CASE_CAPTURE=$TEMP/$CASE_NAME.capture
    SERVER_LOG=$TEMP/$CASE_NAME-server.log
    : >"$CASE_CAPTURE"
    ip netns exec "$GATEWAY_NS" python3 "$TEMP/echo.py" "$CASE_CAPTURE" "$PORT" >"$SERVER_LOG" 2>&1 &
    SERVER_PID=$!
    sleep 0.1

    case "$CASE_NAME" in
        D2O)
            ip netns exec "$GATEWAY_NS" env LD_PRELOAD="$SHIM" "$D2OD_BIN" \
                --queue "$QUEUE" --mode observe --stats 0 >"$CASE_LOG" 2>&1 &
            EXPECTED_ERROR="d2kd: recv из очереди: Input/output error"
            ;;
        R2O)
            ip netns exec "$GATEWAY_NS" env LD_PRELOAD="$SHIM" "$R2OD_BIN" \
                --queue "$QUEUE" --family ipv4 --mode observe --stats 0 \
                --plan "$TEMP/empty.r2op" >"$CASE_LOG" 2>&1 &
            EXPECTED_ERROR="r2o-datapath: ошибка чтения NFQUEUE: Input/output error"
            ;;
        *)
            echo "unknown daemon: $CASE_NAME" >&2
            return 2
            ;;
    esac
    DAEMON_PID=$!

    if ! ip netns exec "$CLIENT_NS" python3 "$TEMP/client.py" "$CASE_LOG" "$PORT" >"$TEMP/$CASE_NAME-client.log" 2>&1; then
        cat "$CASE_LOG" "$SERVER_LOG" "$TEMP/$CASE_NAME-client.log" >&2
        return 1
    fi
    kill -0 "$DAEMON_PID" 2>/dev/null || {
        cat "$CASE_LOG" >&2
        echo "$CASE_NAME daemon exited before the exchange completed" >&2
        return 1
    }
    kill -TERM "$DAEMON_PID" 2>/dev/null || true
    wait "$DAEMON_PID" 2>/dev/null || true
    DAEMON_PID=
    kill -TERM "$SERVER_PID" 2>/dev/null || true
    wait "$SERVER_PID" 2>/dev/null || true
    SERVER_PID=

    FAULT_COUNT=$(grep -Fc 'FAULT-INJECTED recv(EIO) on NFQUEUE socket' "$CASE_LOG" || true)
    if [ "$FAULT_COUNT" -ne 1 ] || ! grep -Fq "$EXPECTED_ERROR" "$CASE_LOG"; then
        cat "$CASE_LOG" >&2
        echo "$CASE_NAME did not log exactly one injected EIO and expected recovery error" >&2
        return 1
    fi
    CAPTURE_COUNT=$(wc -l <"$CASE_CAPTURE")
    if [ "$CAPTURE_COUNT" -ne 64 ]; then
        cat "$CASE_LOG" "$SERVER_LOG" >&2
        echo "$CASE_NAME delivered $CAPTURE_COUNT of 64 UDP requests" >&2
        return 1
    fi
    echo "$CASE_NAME: injected=1 echo=64 recovery=ok"
}

nat_rule_packets() {
    ip netns exec "$GATEWAY_NS" nft list chain inet eio forward |
        awk -v needle="$1" 'index($0, needle) { for (i = 1; i <= NF; i++) if ($i == "packets") { print $(i + 1); found = 1; exit } } END { if (!found) print 0 }'
}

run_nat_case() {
    CASE_NAME=$1
    CASE_LOG=$TEMP/$CASE_NAME-nat.log
    CASE_CAPTURE=$TEMP/$CASE_NAME-nat.capture
    SERVER_LOG=$TEMP/$CASE_NAME-nat-server.log
    CLIENT_LOG=$TEMP/$CASE_NAME-nat-client.log
    SOURCE_PORT=40132
    if [ "$CASE_NAME" = "R2O" ]; then
        SOURCE_PORT=40133
    fi
    : >"$CASE_CAPTURE"
    OUTBOUND_QUEUE_BEFORE=$(nat_rule_packets 'udp dport 19002')
    REPLY_QUEUE_BEFORE=$(nat_rule_packets 'udp sport 19002')
    ip netns exec "$SERVER_NS" python3 "$TEMP/echo.py" \
        "$CASE_CAPTURE" 19002 198.18.78.2 198.18.78.1 >"$SERVER_LOG" 2>&1 &
    SERVER_PID=$!
    sleep 0.1

    case "$CASE_NAME" in
        D2O)
            ip netns exec "$GATEWAY_NS" "$D2OD_BIN" \
                --queue "$QUEUE" --mode observe --stats 0 >"$CASE_LOG" 2>&1 &
            ;;
        R2O)
            ip netns exec "$GATEWAY_NS" "$R2OD_BIN" \
                --queue "$QUEUE" --family ipv4 --mode observe --stats 0 >"$CASE_LOG" 2>&1 &
            ;;
        *)
            echo "unknown daemon: $CASE_NAME" >&2
            return 2
            ;;
    esac
    DAEMON_PID=$!
    sleep 0.1
    kill -0 "$DAEMON_PID" 2>/dev/null || {
        cat "$CASE_LOG" "$SERVER_LOG" >&2
        echo "$CASE_NAME NAT daemon exited during startup" >&2
        return 1
    }

    if ! ip netns exec "$CLIENT_NS" python3 - "$SOURCE_PORT" >"$CLIENT_LOG" 2>&1 <<'PY'
import socket
import sys
import time

source_port = int(sys.argv[1])
destination = ("198.18.78.2", 19002)
sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
sock.bind(("198.18.77.2", source_port))
sock.settimeout(0.1)
for _ in range(40):
    sock.sendto(b"ready", destination)
    try:
        reply, peer = sock.recvfrom(2048)
    except socket.timeout:
        time.sleep(0.025)
        continue
    if reply == b"ready" and peer == destination:
        break
else:
    raise RuntimeError("UDP server did not answer through SNAT")

for index in range(32):
    payload = f"nat-probe-{index:04d}".encode("ascii")
    sock.sendto(payload, destination)
    reply, peer = sock.recvfrom(2048)
    if reply != payload or peer != destination:
        raise RuntimeError(f"NAT reply mismatch: {reply!r} from {peer!r}")
sock.close()
print(f"snat=198.18.78.1 reverse_nat=ok echoes={index + 1}")
PY
    then
        cat "$CASE_LOG" "$SERVER_LOG" "$CLIENT_LOG" >&2
        return 1
    fi
    kill -0 "$DAEMON_PID" 2>/dev/null || {
        cat "$CASE_LOG" >&2
        echo "$CASE_NAME NAT daemon exited after the exchange" >&2
        return 1
    }
    kill -TERM "$DAEMON_PID" 2>/dev/null || true
    wait "$DAEMON_PID" 2>/dev/null || true
    DAEMON_PID=
    kill -TERM "$SERVER_PID" 2>/dev/null || true
    wait "$SERVER_PID" 2>/dev/null || true
    SERVER_PID=

    CAPTURE_COUNT=$(wc -l <"$CASE_CAPTURE")
    SOURCE_COUNT=$(grep -Fc '198.18.78.1:nat-probe-' "$CASE_CAPTURE" || true)
    OUTBOUND_QUEUE_CURRENT=$(nat_rule_packets 'udp dport 19002')
    REPLY_QUEUE_CURRENT=$(nat_rule_packets 'udp sport 19002')
    OUTBOUND_QUEUE_COUNT=$((OUTBOUND_QUEUE_CURRENT - OUTBOUND_QUEUE_BEFORE))
    REPLY_QUEUE_COUNT=$((REPLY_QUEUE_CURRENT - REPLY_QUEUE_BEFORE))
    if [ "$CAPTURE_COUNT" -ne 32 ] || [ "$SOURCE_COUNT" -ne 32 ] \
        || [ "${OUTBOUND_QUEUE_COUNT:-0}" -lt 32 ] || [ "${REPLY_QUEUE_COUNT:-0}" -lt 32 ]; then
        cat "$CASE_LOG" "$SERVER_LOG" "$CLIENT_LOG" >&2
        printf '%s SNAT: translated_sources=%s captures=%s queued_forward=%s queued_reply=%s\n' \
            "$CASE_NAME" "$SOURCE_COUNT" "$CAPTURE_COUNT" \
            "${OUTBOUND_QUEUE_COUNT:-missing}" "${REPLY_QUEUE_COUNT:-missing}" >&2
        return 1
    fi
    if [ "$CASE_NAME" = "D2O" ]; then
        D2O_NAT_QUEUE_COUNTS=$OUTBOUND_QUEUE_COUNT/$REPLY_QUEUE_COUNT
    else
        R2O_NAT_QUEUE_COUNTS=$OUTBOUND_QUEUE_COUNT/$REPLY_QUEUE_COUNT
    fi
    echo "$CASE_NAME: SNAT=198.18.78.1 reverse_nat=ok echoes=32 queued=$OUTBOUND_QUEUE_COUNT/$REPLY_QUEUE_COUNT"
}

run_held_tcp_case() {
    CASE_NAME=$1
    CASE_LOG=$TEMP/$CASE_NAME-held-tcp.log
    CASE_CAPTURE=$TEMP/$CASE_NAME-held-tcp-udp.capture
    TCP_CAPTURE=$TEMP/$CASE_NAME-held-tcp.capture
    FIRST_CAPTURE=$TEMP/$CASE_NAME-held-tcp-first.txt
    SERVER_LOG=$TEMP/$CASE_NAME-held-tcp-udp-server.log
    TRIGGER_PORT=$PORT
    TCP_SERVER_LOG=$TEMP/$CASE_NAME-held-tcp-server.log
    TRIGGER_FILE=$TEMP/$CASE_NAME-eio-trigger
    SOURCE_PORT=40130
    if [ "$CASE_NAME" = "R2O" ]; then
        SOURCE_PORT=40131
    fi
    : >"$CASE_CAPTURE"
    rm -f -- "$TCP_CAPTURE" "$FIRST_CAPTURE" "$TRIGGER_FILE"
    ip netns exec "$GATEWAY_NS" python3 "$TEMP/echo.py" "$CASE_CAPTURE" "$TRIGGER_PORT" >"$SERVER_LOG" 2>&1 &
    SERVER_PID=$!
    ip netns exec "$SERVER_NS" python3 "$TEMP/tcp-hold-server.py" \
        "$FIRST_CAPTURE" "$TCP_CAPTURE" 4450 >"$TCP_SERVER_LOG" 2>&1 &
    TCP_SERVER_PID=$!
    sleep 0.1

    case "$CASE_NAME" in
        D2O)
            ip netns exec "$GATEWAY_NS" env LD_PRELOAD="$SHIM" \
                R2O_NFQ_RECV_EIO_TRIGGER_FILE="$TRIGGER_FILE" "$D2OD_BIN" \
                --queue "$QUEUE" --mode apply --mark 180001 --stats 0 \
                --plan "$TEMP/tcp-hold.d2kp" >"$CASE_LOG" 2>&1 &
            EXPECTED_ERROR="d2kd: recv из очереди: Input/output error"
            ;;
        R2O)
            ip netns exec "$GATEWAY_NS" env LD_PRELOAD="$SHIM" \
                R2O_NFQ_RECV_EIO_TRIGGER_FILE="$TRIGGER_FILE" "$R2OD_BIN" \
                --queue "$QUEUE" --family ipv4 --mode apply --mark 180001 --stats 0 \
                --plan "$TEMP/tcp-hold.r2op" >"$CASE_LOG" 2>&1 &
            EXPECTED_ERROR="r2o-datapath: ошибка чтения NFQUEUE: Input/output error"
            ;;
        *)
            echo "unknown daemon: $CASE_NAME" >&2
            return 2
            ;;
    esac
    DAEMON_PID=$!
    sleep 0.1
    kill -0 "$DAEMON_PID" 2>/dev/null || {
        cat "$CASE_LOG" >&2
        echo "$CASE_NAME held-TCP daemon exited during startup" >&2
        return 1
    }

    if ! ip netns exec "$CLIENT_NS" python3 "$TEMP/tcp-hold-client.py" \
        "$CASE_LOG" "$TRIGGER_FILE" "$FIRST_CAPTURE" "$TCP_CAPTURE" \
        "$TRIGGER_PORT" 4450 "$SOURCE_PORT" >"$TEMP/$CASE_NAME-held-tcp-client.log" 2>&1; then
        cat "$CASE_LOG" "$SERVER_LOG" "$TCP_SERVER_LOG" \
            "$TEMP/$CASE_NAME-held-tcp-client.log" >&2
        return 1
    fi
    kill -0 "$DAEMON_PID" 2>/dev/null || {
        cat "$CASE_LOG" >&2
        echo "$CASE_NAME daemon exited after held-TCP recovery" >&2
        return 1
    }
    kill -TERM "$DAEMON_PID" 2>/dev/null || true
    wait "$DAEMON_PID" 2>/dev/null || true
    DAEMON_PID=
    kill -TERM "$SERVER_PID" "$TCP_SERVER_PID" 2>/dev/null || true
    wait "$SERVER_PID" 2>/dev/null || true
    wait "$TCP_SERVER_PID" 2>/dev/null || true
    SERVER_PID=
    TCP_SERVER_PID=

    FAULT_COUNT=$(grep -Fc 'FAULT-INJECTED recv(EIO) on NFQUEUE socket' "$CASE_LOG" || true)
    if [ "$FAULT_COUNT" -ne 1 ] || ! grep -Fq "$EXPECTED_ERROR" "$CASE_LOG"; then
        cat "$CASE_LOG" >&2
        echo "$CASE_NAME held-TCP run did not log exactly one injected EIO" >&2
        return 1
    fi
    echo "$CASE_NAME: held_tcp=1 injected=1 recovered=1"
}

run_case D2O
run_case R2O
cmp "$TEMP/D2O.capture" "$TEMP/R2O.capture"
run_held_tcp_case D2O
run_held_tcp_case R2O
cmp "$TEMP/D2O-held-tcp.capture" "$TEMP/R2O-held-tcp.capture"
run_nat_case D2O
run_nat_case R2O
cmp "$TEMP/D2O-nat.capture" "$TEMP/R2O-nat.capture"

{
    echo "D2O source: $ACTUAL_D2O_SHA"
    echo "R2O repository revision: $(git -c safe.directory="$ROOT" -C "$ROOT" rev-parse HEAD)"
    echo "R2O binary: $("$R2OD_BIN" --version)"
    grep -E 'FAULT-INJECTED|recv из очереди: Input/output error' "$TEMP/D2O.log"
    grep -E 'FAULT-INJECTED|ошибка чтения NFQUEUE: Input/output error' "$TEMP/R2O.log"
    cat "$TEMP/D2O-client.log" "$TEMP/R2O-client.log"
    cat "$TEMP/D2O-held-tcp-client.log" "$TEMP/R2O-held-tcp-client.log"
    cat "$TEMP/D2O-nat-client.log" "$TEMP/R2O-nat-client.log"
    echo "D2O NAT queue counter deltas (forward/reply): $D2O_NAT_QUEUE_COUNTS"
    echo "R2O NAT queue counter deltas (forward/reply): $R2O_NAT_QUEUE_COUNTS"
    echo "Identical IPv4 NFQUEUE inputs and 64 echo replies matched for D2O and R2O."
    echo "Held TCP originals were flushed after recv(EIO); both production daemons delivered identical TLS bytes."
    echo "Both production daemons preserved IPv4 SNAT and reverse conntrack for 32 UDP exchanges."
} >"$LOG"
cat "$LOG"
