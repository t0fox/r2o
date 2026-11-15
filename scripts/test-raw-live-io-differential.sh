#!/bin/sh
# Live production differential: raw_recv/raw_read_payload/raw_close on real
# loopback raw sockets in netns. C raw_dial/raw_send/raw_read_payload/raw_close
# против Rust RawConn::connect/send_payload_io/read_payload/close.
set -eu

if [ "$(id -u)" -ne 0 ] && [ "${R2O_RAW_IN_USERNS:-0}" != 1 ] &&
    command -v unshare >/dev/null 2>&1; then
    export R2O_RAW_IN_USERNS=1
    exec unshare -Urnm sh -c '
        mount -t tmpfs tmpfs /run 2>/dev/null || true
        mkdir -p /run/netns 2>/dev/null || true
        exec sh "$1"
    ' sh "$0"
fi

ROOT=$(CDPATH='' cd -- "$(dirname -- "$0")/.." && pwd)
D2O_ROOT=${R2O_DONOR_ROOT:?set R2O_DONOR_ROOT}
EXPECTED_D2O_SHA=${R2O_EXPECTED_DONOR_SHA:-a378e230947ebfd011439e1cac0f1e994d883aae}
ACTUAL_D2O_SHA=$(git -C "$D2O_ROOT" rev-parse HEAD)
if [ "$ACTUAL_D2O_SHA" != "$EXPECTED_D2O_SHA" ]; then
    printf 'Expected D2O %s, got %s\n' "$EXPECTED_D2O_SHA" "$ACTUAL_D2O_SHA" >&2
    exit 2
fi
for tool in ip nft python3 cc; do
    command -v "$tool" >/dev/null 2>&1 || {
        echo "missing required command: $tool" >&2
        exit 127
    }
done

TEMP_BASE=${R2O_TEST_TMP:-${ROOT%/r2o}/r2o-tooling/tests}
mkdir -p "$TEMP_BASE"
TEMP=$(mktemp -d "$TEMP_BASE/r2o-raw-live-io.XXXXXX")
NS="r2o-raw-live-io-$$"
SERVER_PID=
cleanup() {
    status=$?
    if ip netns list 2>/dev/null | awk '{print $1}' | grep -Fxq "$NS"; then
        ip netns pids "$NS" 2>/dev/null | xargs -r kill 2>/dev/null || true
        ip netns del "$NS" 2>/dev/null || true
    fi
    if [ "$status" -ne 0 ]; then
        for log in "$TEMP"/*.err "$TEMP"/server.log; do
            [ -f "$log" ] && { echo "== $log" >&2; cat "$log" >&2; }
        done
    fi
    [ "${KEEP_TEST_WORK:-0}" = 1 ] && echo "saved: $TEMP" >&2 || rm -rf "$TEMP"
    exit "$status"
}
trap cleanup EXIT HUP INT TERM

cc -std=gnu11 -O2 -Wall -Wextra -Werror \
    -ffunction-sections -fdata-sections \
    -I"$D2O_ROOT/detect" -I"$D2O_ROOT/detect/include" \
    -I"$D2O_ROOT/core/include" -I"$D2O_ROOT/datapath/include" \
    -o "$TEMP/c-live-io" \
    "$ROOT/crates/r2o-controller/tests/d2o_raw_live_io.c" \
    -Wl,--gc-sections

ip netns add "$NS"
ip netns exec "$NS" ip link set lo up
for table in d2k_rst r2o_rst; do
    ip netns exec "$NS" nft "add table inet $table"
    ip netns exec "$NS" nft "add set inet $table rst4 { type inet_service . ipv4_addr . inet_service; flags timeout; timeout 30s; }"
    ip netns exec "$NS" nft "add set inet $table rst6 { type inet_service . ipv6_addr . inet_service; flags timeout; timeout 30s; }"
    ip netns exec "$NS" nft "add chain inet $table output { type filter hook output priority filter; policy accept; }"
    ip netns exec "$NS" nft "add rule inet $table output tcp flags & rst == rst tcp sport . ip daddr . tcp dport @rst4 drop"
    ip netns exec "$NS" nft "add rule inet $table output tcp flags & rst == rst tcp sport . ip6 daddr . tcp dport @rst6 drop"
done

cat >"$TEMP/server.py" <<'PY'
import socket
import sys
import threading

ready_path, family_text = sys.argv[1], sys.argv[2]
family = socket.AF_INET6 if family_text == "6" else socket.AF_INET
address = "::1" if family == socket.AF_INET6 else "127.0.0.1"
listener = socket.socket(family, socket.SOCK_STREAM)
listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
listener.bind((address, 0))
listener.listen(8)
with open(ready_path, "w", encoding="ascii") as ready:
    ready.write(str(listener.getsockname()[1]))

def serve(connection):
    try:
        data = b""
        while len(data) < 5:
            part = connection.recv(64)
            if not part:
                break
            data += part
        if data[:5] == b"hello":
            connection.sendall(b"reply")
    finally:
        connection.close()

while True:
    connection, _ = listener.accept()
    threading.Thread(target=serve, args=(connection,), daemon=True).start()
PY

run_case() {
    family=$1
    address=$2
    target=$3
    label=$4
    ip netns exec "$NS" python3 "$TEMP/server.py" "$TEMP/ready-$label" "$family" \
        >"$TEMP/server-$label.log" 2>&1 &
    SERVER_PID=$!
    for _ in 1 2 3 4 5 6 7 8 9 10 11 12 13 14 15 16 17 18 19 20; do
        [ -s "$TEMP/ready-$label" ] && break
        kill -0 "$SERVER_PID" 2>/dev/null || { cat "$TEMP/server-$label.log" >&2; exit 1; }
        sleep 0.05
    done
    [ -s "$TEMP/ready-$label" ] || { echo "server did not start" >&2; exit 1; }
    port=$(cat "$TEMP/ready-$label")
    ip netns exec "$NS" env D2K_FW=nft "$TEMP/c-live-io" "$family" "$address" "$port" 800 \
        >"$TEMP/c-$label.out" 2>"$TEMP/c-$label.err"
    ip netns exec "$NS" env R2O_FW=nft \
        R2O_RAW_LIVE_TARGET="$target:$port" R2O_RAW_LIVE_TIMEOUT_MS=800 \
        R2O_RAW_LIVE_OUTPUT="$TEMP/rust-$label.out" \
        cargo test --manifest-path "$ROOT/Cargo.toml" --locked --offline \
        -p r2o-controller --lib raw_probe::tests::raw_live_io_harness \
        -- --exact --ignored --test-threads=1 >"$TEMP/cargo-$label.log" 2>&1
    kill "$SERVER_PID" 2>/dev/null || true
    wait "$SERVER_PID" 2>/dev/null || true
    SERVER_PID=
    if ! diff -u "$TEMP/c-$label.out" "$TEMP/rust-$label.out"; then
        printf 'FAIL: live raw I/O differential %s\n' "$label" >&2
        exit 1
    fi
    printf 'live-io %s: %s\n' "$label" "$(cat "$TEMP/c-$label.out")"
    for table in d2k_rst r2o_rst; do
        for set in rst4 rst6; do
            if ip netns exec "$NS" nft list set inet "$table" "$set" |
                grep -q 'elements = {'; then
                printf 'FAIL: %s %s leaks after %s\n' "$table" "$set" "$label" >&2
                exit 1
            fi
        done
    done
}

run_case 4 127.0.0.1 127.0.0.1 v4
run_case 6 ::1 '[::1]' v6

printf 'PASS: live C/Rust raw recv/read/close match (D2O %s)\n' "$ACTUAL_D2O_SHA"
