#!/bin/sh
# CLI/timing differential d2kvoice vs r2o-controller --voice-check:
# direct STUN (reply/flaky/silent), --wait 0, --mark, --conntrack, exit/stdout.
set -eu

ROOT=$(CDPATH='' cd -- "$(dirname -- "$0")/.." && pwd)
D2O_ROOT=${R2O_DONOR_ROOT:-/mnt/e/d2o-current}
EXPECTED_D2O_SHA=7a5fab97a1a7f0f00ebb906dba7ed568cdc0ca05
ACTUAL_D2O_SHA=$(git -C "$D2O_ROOT" rev-parse HEAD)
CC=${CC:-cc}
CARGO=${CARGO:-cargo}
TMPDIR=${TMPDIR:-/tmp}

if [ "$ACTUAL_D2O_SHA" != "$EXPECTED_D2O_SHA" ]; then
    printf 'Expected D2O current %s, got %s\n' "$EXPECTED_D2O_SHA" "$ACTUAL_D2O_SHA" >&2
    exit 2
fi

TEMP=$(mktemp -d "$TMPDIR/r2o-voice-cli.XXXXXX")
trap 'rm -rf -- "$TEMP"' EXIT HUP INT TERM
: >"$TEMP/empty.txt"
# C ищет приманки в D2K_FAKE_DIR; Rust держит те же байты в assets. Даём
# C те же файлы, иначе blocked-ветка сравнивала бы «файлов нет» с реальным
# перебором.
mkdir -p "$TEMP/fake"
cp "$ROOT/crates/r2o-controller/assets/voice/stun.bin" "$TEMP/fake/"
cp "$ROOT/crates/r2o-controller/assets/voice/quic_initial_dbankcloud_ru.bin" "$TEMP/fake/"

make -s -B -C "$D2O_ROOT/core" tcp1620_whitelist.inc hello_profiles.inc d2kvoice CC="$CC" >/dev/null
D2O_VOICE="$D2O_ROOT/core/d2kvoice"
"$CARGO" build --manifest-path "$ROOT/Cargo.toml" --locked --offline \
    -q -p r2o-controller --bin r2o-controller
R2O="$ROOT/target/debug/r2o-controller"
SERVER="$ROOT/scripts/fixtures/voice_stun_server.py"

start_server() {
    mode=$1
    python3 "$SERVER" "$mode" >"$TEMP/server-$mode.port" 2>"$TEMP/server-$mode.err" &
    server_pid=$!
    attempt=0
    port=
    while [ -z "$port" ] && [ "$attempt" -lt 100 ]; do
        port=$(sed -n 1p "$TEMP/server-$mode.port" 2>/dev/null || true)
        [ -n "$port" ] || sleep 0.02
        attempt=$((attempt + 1))
    done
    [ -n "$port" ] || { echo "STUN-сервер $mode не поднялся" >&2; cat "$TEMP/server-$mode.err" >&2; exit 1; }
    SERVER_PORT=$port
}

stop_server() {
    kill "$server_pid" 2>/dev/null || true
    wait "$server_pid" 2>/dev/null || true
    server_pid=
}

normalize() {
    sed -E \
        -e 's/127\.0\.0\.1:[0-9]+/127.0.0.1:PORT/g' \
        -e 's/за [0-9]+ мс/за N мс/g' \
        "$1"
}

run_one() {
    impl=$1
    mode=$2
    shift 2
    start_server "$mode"
    set +e
    if [ "$impl" = c ]; then
        start_ns=$(date +%s%N)
        D2K_FAKE_DIR="$TEMP/fake" "$D2O_VOICE" --addr "127.0.0.1:$SERVER_PORT" \
            --control 127.0.0.1:9 --conntrack "$TEMP/empty.txt" "$@" \
            >"$TEMP/$impl.out" 2>"$TEMP/$impl.err"
        status=$?
        end_ns=$(date +%s%N)
    else
        start_ns=$(date +%s%N)
        "$R2O" --voice-check --addr "127.0.0.1:$SERVER_PORT" --control 127.0.0.1:9 \
            --conntrack "$TEMP/empty.txt" "$@" >"$TEMP/$impl.out" 2>"$TEMP/$impl.err"
        status=$?
        end_ns=$(date +%s%N)
    fi
    set -e
    duration_ms=$(( (end_ns - start_ns) / 1000000 ))
    stop_server
    normalize "$TEMP/$impl.out" >"$TEMP/$impl.norm"
    LAST_STATUS=$status
    LAST_DURATION=$duration_ms
}

run_case() {
    name=$1
    mode=$2
    shift 2
    run_one c "$mode" "$@"
    c_status=$LAST_STATUS
    c_duration=$LAST_DURATION
    run_one r "$mode" "$@"
    r_status=$LAST_STATUS
    r_duration=$LAST_DURATION
    if [ "$c_status" != "$r_status" ]; then
        echo "FAIL $name exit C=$c_status Rust=$r_status" >&2
        cat "$TEMP/c.norm" "$TEMP/r.norm" >&2
        exit 1
    fi
    if ! diff -u "$TEMP/c.norm" "$TEMP/r.norm"; then
        echo "FAIL $name stdout" >&2
        exit 1
    fi
    delta=$((c_duration - r_duration))
    [ "$delta" -lt 0 ] && delta=$((-delta))
    if [ "$delta" -gt 2000 ]; then
        echo "FAIL $name timing C=${c_duration}ms Rust=${r_duration}ms" >&2
        exit 1
    fi
    printf '%s: exit=%s duration_c=%sms duration_r=%sms\n' \
        "$name" "$c_status" "$c_duration" "$r_duration"
}

run_case reply_wait0 reply --wait 0 --mark 0x2d
run_case reply_wait100 reply --wait 100 --mark 0x2d
run_case reply_nomark reply --wait 100
run_case flaky_wait100 flaky --wait 100 --mark 0x2d
run_case silent_wait100 silent --wait 100 --mark 0x2d
run_case junk_wait_mark reply --wait abc --mark zz

# CLI-ошибки: C usage/exit 2; stdout пустой у обеих сторон.
set +e
"$D2O_VOICE" --wait >"$TEMP/c-missing.out" 2>"$TEMP/c-missing.err"
c_status=$?
"$R2O" --voice-check --wait >"$TEMP/r-missing.out" 2>"$TEMP/r-missing.err"
r_status=$?
set -e
[ "$c_status" = "$r_status" ] || { echo "FAIL missing_wait exit C=$c_status Rust=$r_status" >&2; exit 1; }
[ ! -s "$TEMP/c-missing.out" ] && [ ! -s "$TEMP/r-missing.out" ] || {
    echo "FAIL missing_wait stdout не пуст" >&2; exit 1; }

set +e
"$D2O_VOICE" --addr example.com:9 >"$TEMP/c-addr.out" 2>"$TEMP/c-addr.err"
c_status=$?
"$R2O" --voice-check --addr example.com:9 >"$TEMP/r-addr.out" 2>"$TEMP/r-addr.err"
r_status=$?
set -e
[ "$c_status" = "$r_status" ] || { echo "FAIL bad_addr exit C=$c_status Rust=$r_status" >&2; exit 1; }

# Conntrack/alive-threshold пути: цель 203.0.113.8 в TEST-NET-3, контроль —
# loopback silent STUN. Проверяем young/silent/answers и контрольный отказ.
make_fixture() {
    name=$1
    packets=$2
    replied=$3
    line="ipv4 2 udp 17 29 src=192.168.1.10 dst=203.0.113.8 sport=40000 dport=50000 packets=$packets bytes=1000"
    [ "$replied" = yes ] || line="$line [UNREPLIED]"
    line="$line src=203.0.113.8 dst=192.168.1.10 sport=50000 dport=40000 packets=5 bytes=500 mark=0 use=1"
    printf '%s\n' "$line" >"$TEMP/$name.txt"
}

run_conntrack_case() {
    name=$1
    fixture=$2
    control_mode=$3
    shift 3
    run_conntrack_one() {
        impl=$1
        shift
        start_server "$control_mode"
        control_port=$SERVER_PORT
        set +e
        start_ns=$(date +%s%N)
        if [ "$impl" = c ]; then
            D2K_FAKE_DIR="$TEMP/fake" "$D2O_VOICE" --addr 203.0.113.8:50000 \
                --control "127.0.0.1:$control_port" --conntrack "$fixture" "$@" \
                >"$TEMP/$impl.out" 2>"$TEMP/$impl.err"
        else
            "$R2O" --voice-check --addr 203.0.113.8:50000 \
                --control "127.0.0.1:$control_port" --conntrack "$fixture" "$@" \
                >"$TEMP/$impl.out" 2>"$TEMP/$impl.err"
        fi
        status=$?
        end_ns=$(date +%s%N)
        set -e
        duration_ms=$(( (end_ns - start_ns) / 1000000 ))
        stop_server
        normalize "$TEMP/$impl.out" >"$TEMP/$impl.norm"
        LAST_STATUS=$status
        LAST_DURATION=$duration_ms
    }
    run_conntrack_one c "$@"
    c_status=$LAST_STATUS
    c_duration=$LAST_DURATION
    run_conntrack_one r "$@"
    r_status=$LAST_STATUS
    r_duration=$LAST_DURATION
    if [ "$c_status" != "$r_status" ]; then
        echo "FAIL $name exit C=$c_status Rust=$r_status" >&2
        cat "$TEMP/c.norm" "$TEMP/r.norm" >&2
        exit 1
    fi
    if ! diff -u "$TEMP/c.norm" "$TEMP/r.norm"; then
        echo "FAIL $name stdout" >&2
        exit 1
    fi
    delta=$((c_duration - r_duration))
    [ "$delta" -lt 0 ] && delta=$((-delta))
    if [ "$delta" -gt 2000 ]; then
        echo "FAIL $name timing C=${c_duration}ms Rust=${r_duration}ms" >&2
        exit 1
    fi
    printf '%s: exit=%s duration_c=%sms duration_r=%sms\n' \
        "$name" "$c_status" "$c_duration" "$r_duration"
}

make_fixture voice_young 2 no
make_fixture voice_silent 10 no
make_fixture voice_answers 10 yes
run_conntrack_case conntrack_young "$TEMP/voice_young.txt" silent --wait 100
run_conntrack_case conntrack_silent "$TEMP/voice_silent.txt" silent --wait 100
run_conntrack_case conntrack_silent_discovery "$TEMP/voice_silent.txt" silent --wait 100 --discovery
run_conntrack_case conntrack_blocked "$TEMP/voice_silent.txt" reply --wait 100
run_conntrack_case conntrack_answers "$TEMP/voice_answers.txt" silent --wait 100

printf 'PASS: d2kvoice/r2o-controller direct STUN CLI/timing (D2O %s)\n' "$ACTUAL_D2O_SHA"
