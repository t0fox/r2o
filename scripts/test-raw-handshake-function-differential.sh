#!/bin/sh
# Production C/Rust differential: d2k_raw_probe_handshake_as vs RawConn::connect.
# Success, RST, timeout, IPv4/IPv6 — в одном netns, без test-only I/O seam.
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
[ "$(uname -s)" = Linux ] || { echo "requires Linux" >&2; exit 77; }
for tool in ip nft python3 cc; do
    command -v "$tool" >/dev/null 2>&1 || {
        echo "missing required command: $tool" >&2
        exit 127
    }
done

TEMP_BASE=${R2O_TEST_TMP:-${ROOT%/r2o}/r2o-tooling/tests}
mkdir -p "$TEMP_BASE"
TEMP=$(mktemp -d "$TEMP_BASE/r2o-raw-handshake-fn.XXXXXX")
NS="r2o-raw-handshake-fn-$$"
SERVER_PID=
cleanup() {
    status=$?
    if ip netns list 2>/dev/null | awk '{print $1}' | grep -Fxq "$NS"; then
        ip netns pids "$NS" 2>/dev/null | xargs -r kill 2>/dev/null || true
        ip netns del "$NS" 2>/dev/null || true
    fi
    if [ "$status" -ne 0 ]; then
        [ -f "$TEMP/server.log" ] && cat "$TEMP/server.log" >&2 || true
        [ -f "$TEMP/cargo.log" ] && tail -30 "$TEMP/cargo.log" >&2 || true
    fi
    if [ "${KEEP_TEST_WORK:-0}" = 1 ]; then
        echo "saved: $TEMP" >&2
    else
        rm -rf "$TEMP"
    fi
    exit "$status"
}
trap cleanup EXIT HUP INT TERM

cc -std=gnu11 -O2 -Wall -Wextra -Werror \
    -ffunction-sections -fdata-sections \
    -I"$D2O_ROOT/detect" -I"$D2O_ROOT/detect/include" \
    -I"$D2O_ROOT/core/include" -I"$D2O_ROOT/datapath/include" \
    -o "$TEMP/c-handshake" \
    "$ROOT/crates/r2o-controller/tests/d2o_raw_handshake_production.c" \
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
ip netns exec "$NS" ip route add 10.255.255.0/24 dev lo
cat >"$TEMP/server.py" <<'PY'
import json
import socket
import sys
import threading

ready_path = sys.argv[1]
listeners = {}
closed = {}
for family, address, key in (
    (socket.AF_INET, "127.0.0.1", "v4"),
    (socket.AF_INET6, "::1", "v6"),
):
    listener = socket.socket(family, socket.SOCK_STREAM)
    listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    listener.bind((address, 0))
    listener.listen(8)
    listeners[key] = listener
    unused = socket.socket(family, socket.SOCK_STREAM)
    unused.bind((address, 0))
    closed[key] = unused.getsockname()[1]
    unused.close()

unused = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
unused.bind(("127.0.0.1", 0))
drop = unused.getsockname()[1]
unused.close()

with open(ready_path, "w", encoding="ascii") as ready:
    json.dump(
        {
            "v4-success": listeners["v4"].getsockname()[1],
            "v6-success": listeners["v6"].getsockname()[1],
            "v4-rst": closed["v4"],
            "v6-rst": closed["v6"],
            "drop": drop,
        },
        ready,
    )

def serve(listener):
    while True:
        connection, _ = listener.accept()
        connection.close()

for listener in listeners.values():
    threading.Thread(target=serve, args=(listener,), daemon=True).start()
threading.Event().wait()
PY

ip netns exec "$NS" python3 "$TEMP/server.py" "$TEMP/ready" >"$TEMP/server.log" 2>&1 &
SERVER_PID=$!
for _ in 1 2 3 4 5 6 7 8 9 10 11 12 13 14 15 16 17 18 19 20; do
    [ -s "$TEMP/ready" ] && break
    kill -0 "$SERVER_PID" 2>/dev/null || { cat "$TEMP/server.log" >&2; exit 1; }
    sleep 0.05
done
[ -s "$TEMP/ready" ] || { echo "server did not start" >&2; exit 1; }

port_of() {
    python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))[sys.argv[2]])' "$TEMP/ready" "$1"
}

run_case() {
    name=$1
    family=$2
    address=$3
    port=$4
    timeout=$5
    target="$address:$port"
    if [ "$family" = 6 ]; then
        target="[$address]:$port"
    fi
    ip netns exec "$NS" env D2K_FW=nft "$TEMP/c-handshake" \
        "$family" "$address" "$port" "$timeout" >"$TEMP/c-$name.out"
    ip netns exec "$NS" env R2O_FW=nft \
        R2O_RAW_CONNECT_TARGET="$target" \
        R2O_RAW_CONNECT_TIMEOUT_MS="$timeout" \
        R2O_RAW_CONNECT_OUTPUT="$TEMP/rust-$name.out" \
        cargo test --manifest-path "$ROOT/Cargo.toml" --locked --offline \
        -p r2o-controller --lib \
        raw_probe::tests::raw_connect_production_harness \
        -- --exact --ignored --test-threads=1 >"$TEMP/cargo.log" 2>&1
    if ! diff -u "$TEMP/c-$name.out" "$TEMP/rust-$name.out"; then
        printf 'FAIL: raw handshake function differential %s\n' "$name" >&2
        exit 1
    fi
    printf 'handshake-fn %s: %s\n' "$name" "$(cat "$TEMP/c-$name.out")"
    for table in d2k_rst r2o_rst; do
        for set in rst4 rst6; do
            if ip netns exec "$NS" nft list set inet "$table" "$set" |
                grep -q 'elements = {'; then
                printf 'FAIL: %s %s leaks after %s\n' "$table" "$set" "$name" >&2
                exit 1
            fi
        done
    done
}

run_case v4-success 4 127.0.0.1 "$(port_of v4-success)" 300
run_case v6-success 6 ::1 "$(port_of v6-success)" 300
run_case v4-rst 4 127.0.0.1 "$(port_of v4-rst)" 300
run_case v6-rst 6 ::1 "$(port_of v6-rst)" 300
run_case v4-timeout 4 10.255.255.1 443 200

printf 'PASS: C/Rust raw handshake function success/RST/timeout IPv4/IPv6 match (D2O %s)\n' \
    "$ACTUAL_D2O_SHA"
