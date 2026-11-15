#!/bin/sh
# Production C/Rust differential: d2k_raw_probe_poison_family против
# raw_probe_once на loopback raw-сокетах. Poison: badsum/split/seqovl/
# syn_data/none, RST на закрытом порту и timeout на blackhole-маршруте.
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
TEMP=$(mktemp -d "$TEMP_BASE/r2o-raw-poison.XXXXXX")
NS="r2o-raw-poison-$$"
SERVER_PID=
cleanup() {
    status=$?
    if ip netns list 2>/dev/null | awk '{print $1}' | grep -Fxq "$NS"; then
        ip netns pids "$NS" 2>/dev/null | xargs -r kill 2>/dev/null || true
        ip netns del "$NS" 2>/dev/null || true
    fi
    if [ "$status" -ne 0 ]; then
        for log in "$TEMP"/*.err "$TEMP"/*.log; do
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
    -o "$TEMP/c-poison" \
    "$ROOT/crates/r2o-controller/tests/d2o_raw_poison_live.c" \
    "$D2O_ROOT/detect/poison.c" "$D2O_ROOT/detect/trigger.c" \
    "$D2O_ROOT/core/measured.c" "$D2O_ROOT/core/plantlv.c" \
    "$D2O_ROOT/core/hello.c" "$D2O_ROOT/core/meas.c" \
    "$D2O_ROOT/core/link.c" "$D2O_ROOT/core/quic.c" \
    "$D2O_ROOT/core/quicwire.c" "$D2O_ROOT/core/crypto.c" \
    "$D2O_ROOT/datapath/plan_parse.c" "$D2O_ROOT/datapath/plan_apply.c" \
    "$D2O_ROOT/datapath/wire.c" -Wl,--gc-sections -lpthread

ip netns add "$NS"
ip netns exec "$NS" ip link set lo up
ip netns exec "$NS" ip route add 10.255.255.0/24 dev lo
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
listener.listen(64)
with open(ready_path, "w", encoding="ascii") as ready:
    ready.write(str(listener.getsockname()[1]))

def serve(connection):
    try:
        connection.settimeout(0.5)
        data = b""
        try:
            while len(data) < 4096:
                part = connection.recv(4096)
                if not part:
                    break
                data += part
                if len(data) >= 1:
                    break
        except socket.timeout:
            pass
        if data:
            connection.sendall(b"reply")
    except OSError:
        pass
    finally:
        connection.close()

while True:
    connection, _ = listener.accept()
    threading.Thread(target=serve, args=(connection,), daemon=True).start()
PY

start_server() {
    family=$1
    label=$2
    ip netns exec "$NS" python3 "$TEMP/server.py" "$TEMP/ready-$label" "$family" \
        >"$TEMP/server-$label.log" 2>&1 &
    SERVER_PID=$!
    for _ in 1 2 3 4 5 6 7 8 9 10 11 12 13 14 15 16 17 18 19 20; do
        [ -s "$TEMP/ready-$label" ] && break
        kill -0 "$SERVER_PID" 2>/dev/null || { cat "$TEMP/server-$label.log" >&2; exit 1; }
        sleep 0.05
    done
    [ -s "$TEMP/ready-$label" ] || { echo "server did not start" >&2; exit 1; }
}

wait_server() {
    kill "$SERVER_PID" 2>/dev/null || true
    wait "$SERVER_PID" 2>/dev/null || true
    SERVER_PID=
}

port_of() {
    python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))[sys.argv[2]])' "$TEMP/ready-v4" "$1"
}

run_open_case() {
    family=$1
    address=$2
    target=$3
    label=$4
    port=$5
    poison=$6
    wrapper=${7:-}
    if [ -n "$wrapper" ]; then
        ip netns exec "$NS" env D2K_FW=nft "$TEMP/c-poison" "$family" "$address" "$port" 500 "$poison" "$wrapper" \
            >"$TEMP/c-$label.out" 2>"$TEMP/c-$label.err"
    else
        ip netns exec "$NS" env D2K_FW=nft "$TEMP/c-poison" "$family" "$address" "$port" 500 "$poison" \
            >"$TEMP/c-$label.out" 2>"$TEMP/c-$label.err"
    fi
    ip netns exec "$NS" env R2O_FW=nft \
        R2O_RAW_POISON_TARGET="$target:$port" R2O_RAW_POISON_TIMEOUT_MS=500 \
        R2O_RAW_POISON_NAME="$poison" R2O_RAW_POISON_OUTPUT="$TEMP/rust-$label.out" \
        cargo test --manifest-path "$ROOT/Cargo.toml" --locked --offline \
        -p r2o-controller --lib raw_probe::tests::raw_poison_production_harness \
        -- --exact --ignored --test-threads=1 >"$TEMP/cargo-$label.log" 2>&1
    if ! diff -u "$TEMP/c-$label.out" "$TEMP/rust-$label.out"; then
        printf 'FAIL: raw poison differential %s\n' "$label" >&2
        exit 1
    fi
    printf 'poison-live %s: %s\n' "$label" "$(cat "$TEMP/c-$label.out")"
}

run_error_case() {
    family=$1
    address=$2
    target=$3
    label=$4
    port=$5
    poison=$6
    ip netns exec "$NS" env D2K_FW=nft "$TEMP/c-poison" "$family" "$address" "$port" 300 "$poison" \
        >"$TEMP/c-$label.out" 2>"$TEMP/c-$label.err"
    ip netns exec "$NS" env R2O_FW=nft \
        R2O_RAW_POISON_TARGET="$target:$port" R2O_RAW_POISON_TIMEOUT_MS=300 \
        R2O_RAW_POISON_NAME="$poison" R2O_RAW_POISON_OUTPUT="$TEMP/rust-$label.out" \
        cargo test --manifest-path "$ROOT/Cargo.toml" --locked --offline \
        -p r2o-controller --lib raw_probe::tests::raw_poison_production_harness \
        -- --exact --ignored --test-threads=1 >"$TEMP/cargo-$label.log" 2>&1
    if ! diff -u "$TEMP/c-$label.out" "$TEMP/rust-$label.out"; then
        printf 'FAIL: raw poison error differential %s\n' "$label" >&2
        exit 1
    fi
    printf 'poison-live %s: %s\n' "$label" "$(cat "$TEMP/c-$label.out")"
}

start_server 4 v4
V4=$(cat "$TEMP/ready-v4")
for poison in badsum split seqovl syn_data none; do
    run_open_case 4 127.0.0.1 127.0.0.1 "v4-$poison" "$V4" "$poison"
done
run_open_case 4 127.0.0.1 127.0.0.1 "v4-wrapper" "$V4" badsum wrapper
wait_server
start_server 6 v6
V6=$(cat "$TEMP/ready-v6")
for poison in badsum split seqovl syn_data none; do
    run_open_case 6 ::1 '[::1]' "v6-$poison" "$V6" "$poison"
done
wait_server
# Закрытый loopback-порт: RST на SYN.
CLOSED=$(python3 -c 'import socket; s=socket.socket(); s.bind(("127.0.0.1",0)); print(s.getsockname()[1]); s.close()')
run_error_case 4 127.0.0.1 127.0.0.1 v4-rst "$CLOSED" badsum
# Blackhole-маршрут: SYN-ACK не приходит.
run_error_case 4 10.255.255.1 10.255.255.1 v4-timeout 443 badsum

printf 'PASS: production C/Rust raw poison family match (D2O %s)\n' "$ACTUAL_D2O_SHA"
