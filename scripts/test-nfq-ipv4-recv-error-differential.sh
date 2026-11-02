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
CLIENT_IF=ec$$
GATEWAY_IF=eg$$
DAEMON_PID=
SERVER_PID=

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
    ip netns pids "$CLIENT_NS" 2>/dev/null | xargs -r kill -TERM 2>/dev/null || true
    ip netns pids "$GATEWAY_NS" 2>/dev/null | xargs -r kill -TERM 2>/dev/null || true
    ip netns del "$CLIENT_NS" 2>/dev/null || true
    ip netns del "$GATEWAY_NS" 2>/dev/null || true
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
"$R2OD_BIN" --plan "$TEMP/empty.r2op" --mode observe --check >/dev/null

cat >"$TEMP/echo.py" <<'PY'
import socket
import sys

capture_path, port = sys.argv[1], int(sys.argv[2])
sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
sock.bind(("198.18.77.1", port))
with open(capture_path, "w", encoding="ascii", buffering=1) as capture:
    while True:
        payload, peer = sock.recvfrom(2048)
        if payload != b"ready":
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

ip netns add "$CLIENT_NS"
ip netns add "$GATEWAY_NS"
ip link add "$CLIENT_IF" type veth peer name "$GATEWAY_IF"
ip link set "$CLIENT_IF" netns "$CLIENT_NS"
ip link set "$GATEWAY_IF" netns "$GATEWAY_NS"
ip -n "$CLIENT_NS" link set lo up
ip -n "$GATEWAY_NS" link set lo up
ip -n "$CLIENT_NS" addr add 198.18.77.2/24 dev "$CLIENT_IF"
ip -n "$GATEWAY_NS" addr add 198.18.77.1/24 dev "$GATEWAY_IF"
ip -n "$CLIENT_NS" link set "$CLIENT_IF" up
ip -n "$GATEWAY_NS" link set "$GATEWAY_IF" up
ip netns exec "$GATEWAY_NS" nft add table inet eio
ip netns exec "$GATEWAY_NS" nft 'add chain inet eio input { type filter hook input priority 0; policy accept; }'
ip netns exec "$GATEWAY_NS" nft add rule inet eio input ip protocol udp udp dport "$PORT" queue num "$QUEUE" bypass

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

run_case D2O
run_case R2O
cmp "$TEMP/D2O.capture" "$TEMP/R2O.capture"

{
    echo "D2O source: $ACTUAL_D2O_SHA"
    echo "R2O source: $(git -c safe.directory="$ROOT" -C "$ROOT" rev-parse HEAD)"
    grep -E 'FAULT-INJECTED|recv из очереди: Input/output error' "$TEMP/D2O.log"
    grep -E 'FAULT-INJECTED|ошибка чтения NFQUEUE: Input/output error' "$TEMP/R2O.log"
    cat "$TEMP/D2O-client.log" "$TEMP/R2O-client.log"
    echo "Identical IPv4 NFQUEUE inputs and 64 echo replies matched for D2O and R2O."
} >"$LOG"
cat "$LOG"