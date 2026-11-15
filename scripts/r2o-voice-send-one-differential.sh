#!/bin/sh
# C/Rust differential: voice send_one/voice_ask datagram trace на loopback.
# C: d2k_voice_arm_plan + d2k_udp_plan_send; Rust: production
# r2o_ask_voice_with_arm. Сверяются байты/порядок/количество, TTL (IP_RECVTTL)
# и tally (pass/fail/err/marked/rtt) для copies 0/1/2/3.
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
TEMP=$(mktemp -d "$TMPDIR/r2o-voice-send.XXXXXX")
trap '[ -z "${receiver_pid:-}" ] || kill "$receiver_pid" 2>/dev/null || true; rm -rf -- "$TEMP"' EXIT HUP INT TERM

make -s -B -C "$DONOR/core" d2kvoice CC="$CC" >/dev/null
(
    cd "$DONOR/core"
    "$CC" -std=gnu11 -O2 -Wall -Wextra -Werror \
        -I. -Iinclude -I../datapath/include -I../runtime \
        -o "$TEMP/c" \
        "$ROOT/crates/r2o-controller/tests/d2o_voice_send_one_differential.c" \
        voice_discovery.o stun.o net4.o tls13core.o crypto.o x25519.o meas.o \
        diagnostics.o libd2k_udp.a -lpthread
)

"$CARGO" test --manifest-path "$ROOT/Cargo.toml" --locked --offline \
    -p r2o-controller --lib --no-run >/dev/null 2>&1

RECEIVER="$ROOT/scripts/fixtures/voice_send_trace_receiver.py"
start_receiver() {
    tag=$1
    python3 "$RECEIVER" >"$TEMP/$tag.port" 2>"$TEMP/$tag.err" &
    receiver_pid=$!
    attempt=0
    port=
    while [ -z "$port" ] && [ "$attempt" -lt 100 ]; do
        port=$(sed -n 1p "$TEMP/$tag.port" 2>/dev/null || true)
        [ -n "$port" ] || sleep 0.02
        attempt=$((attempt + 1))
    done
    [ -n "$port" ] || {
        echo "voice trace receiver не поднялся" >&2
        cat "$TEMP/$tag.err" >&2
        exit 1
    }
}

run_case() {
    copies=$1
    start_receiver c
    c_port=$port
    "$TEMP/c" "127.0.0.1:$c_port" "$copies" 150 >"$TEMP/c.tally"
    wait "$receiver_pid"

    start_receiver r
    r_port=$port
    R2O_VOICE_SEND_SERVER="127.0.0.1:$r_port" \
    R2O_VOICE_SEND_COPIES="$copies" \
    R2O_VOICE_SEND_WAIT_MS=150 \
    R2O_VOICE_SEND_OUTPUT="$TEMP/r.tally" \
        "$CARGO" test --manifest-path "$ROOT/Cargo.toml" --locked --offline \
        -p r2o-controller --lib \
        voice_measure::tests::voice_send_one_diagnostic_trace_matches_c \
        -- --exact --nocapture \
        >"$TEMP/r.log" 2>&1
    wait "$receiver_pid"

    cp "$TEMP/c.port" "$TEMP/c.trace"
    cp "$TEMP/r.port" "$TEMP/r.trace"
    # Приёмник печатает порт первой строкой; сама трасса — со второй.
    sed -i '1d' "$TEMP/c.trace" "$TEMP/r.trace"
    if ! diff -u "$TEMP/c.trace" "$TEMP/r.trace"; then
        echo "FAIL traces copies=$copies" >&2
        cat "$TEMP/r.log" >&2
        exit 1
    fi
    if ! diff -u "$TEMP/c.tally" "$TEMP/r.tally"; then
        echo "FAIL tally copies=$copies" >&2
        cat "$TEMP/r.tally" >&2
        exit 1
    fi
    printf 'copies=%s datagrams=%s %s' "$copies" \
        "$(wc -l <"$TEMP/c.trace")" "$(cat "$TEMP/c.tally")"
}

run_case 0
run_case 1
run_case 2
run_case 3
printf 'PASS: voice send_one datagram trace matches C (%s).\n' "$ACTUAL_SHA"
