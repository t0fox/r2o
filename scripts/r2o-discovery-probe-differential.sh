#!/bin/sh
# C/Rust differential: voice_discovery `discovery_probe` на loopback.
# C: discovery_probe; Rust: production r2o_probe_discovery_endpoint.
# Сверяются 25 запросов (первый — планом с prefix, остальные — прямым send),
# SSRC (маскируется в трассе, но ответ эхо-проверяется приёмником), байты,
# TTL (IP_RECVTTL), mark и ошибки.
set -eu

ROOT=$(CDPATH='' cd -- "$(dirname -- "$0")/.." && pwd)
DONOR=${R2O_DONOR_ROOT:-/mnt/e/d2o-current}
EXPECTED_SHA=7a5fab97a1a7f0f00ebb906dba7ed568cdc0ca05
ACTUAL_SHA=$(git -C "$DONOR" rev-parse HEAD)
[ "$ACTUAL_SHA" = "$EXPECTED_SHA" ] || {
    printf 'Expected D2O %s, got %s\n' "$EXPECTED_SHA" "$ACTUAL_SHA" >&2
    exit 2
}
CC=${CC:-cc}
CARGO=${CARGO:-cargo}
TMPDIR=${TMPDIR:-/tmp}
TEMP=$(mktemp -d "$TMPDIR/r2o-discovery-probe.XXXXXX")
trap '[ -z "${receiver_pid:-}" ] || kill "$receiver_pid" 2>/dev/null || true; rm -rf -- "$TEMP"' EXIT HUP INT TERM

make -s -B -C "$DONOR/core" libd2k_udp.a meas.o diagnostics.o CC="$CC" >/dev/null
(
    cd "$DONOR/core"
    "$CC" -std=gnu11 -O2 -Wall -Wextra -Werror \
        -I. -Iinclude -I../datapath/include -I../runtime \
        -o "$TEMP/c" \
        "$ROOT/crates/r2o-controller/tests/d2o_discovery_probe_differential.c" \
        stun.o net4.o tls13core.o crypto.o x25519.o meas.o diagnostics.o \
        libd2k_udp.a -lpthread
)
"$CARGO" test --manifest-path "$ROOT/Cargo.toml" --locked --offline \
    -p r2o-controller --lib --no-run >/dev/null 2>&1

RECEIVER="$ROOT/scripts/fixtures/discovery_trace_receiver.py"
start_receiver() {
    tag=$1
    empty_seconds=${2:-60}
    TRACE_EMPTY_SECONDS="$empty_seconds" python3 "$RECEIVER" \
        >"$TEMP/$tag.port" 2>"$TEMP/$tag.err" &
    receiver_pid=$!
    attempt=0
    port=
    while [ -z "$port" ] && [ "$attempt" -lt 100 ]; do
        port=$(sed -n 1p "$TEMP/$tag.port" 2>/dev/null || true)
        [ -n "$port" ] || sleep 0.02
        attempt=$((attempt + 1))
    done
    [ -n "$port" ] || {
        echo "discovery trace receiver не поднялся" >&2
        cat "$TEMP/$tag.err" >&2
        exit 1
    }
}

run_case() {
    name=$1
    mark=$2
    use_prefix=$3
    empty_seconds=60
    [ "$mark" = 46 ] && empty_seconds=5
    start_receiver c "$empty_seconds"
    c_port=$port
    "$TEMP/c" "127.0.0.1:$c_port" 300 "$mark" "$use_prefix" >"$TEMP/c.tally"
    wait "$receiver_pid"

    start_receiver r "$empty_seconds"
    r_port=$port
    R2O_DISCOVERY_SEND_SERVER="127.0.0.1:$r_port" \
    R2O_DISCOVERY_SEND_WAIT_MS=300 \
    R2O_DISCOVERY_SEND_MARK="$mark" \
    R2O_DISCOVERY_SEND_PREFIX="$use_prefix" \
    R2O_DISCOVERY_SEND_OUTPUT="$TEMP/r.tally" \
        "$CARGO" test --manifest-path "$ROOT/Cargo.toml" --locked --offline \
        -p r2o-controller --lib \
        voice_discovery::tests::discovery_probe_diagnostic_trace_matches_c \
        -- --exact --nocapture >"$TEMP/r.log" 2>&1
    wait "$receiver_pid"

    cp "$TEMP/c.port" "$TEMP/c.trace"
    cp "$TEMP/r.port" "$TEMP/r.trace"
    sed -i '1d' "$TEMP/c.trace" "$TEMP/r.trace"
    if ! diff -u "$TEMP/c.trace" "$TEMP/r.trace"; then
        echo "FAIL trace $name" >&2
        cat "$TEMP/r.log" >&2
        exit 1
    fi
    if ! diff -u "$TEMP/c.tally" "$TEMP/r.tally"; then
        echo "FAIL tally $name" >&2
        cat "$TEMP/r.tally" >&2
        exit 1
    fi
    printf '%s datagrams=%s %s' "$name" "$(wc -l <"$TEMP/c.trace")" \
        "$(cat "$TEMP/c.tally")"
}

run_case prefix-mark0 0 1
run_case no-prefix-mark0 0 0
run_case prefix-mark46 46 1
printf 'PASS: discovery_probe datagram trace matches C (%s).\n' "$ACTUAL_SHA"
