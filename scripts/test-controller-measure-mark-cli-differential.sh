#!/bin/sh
# CLI differential `--measure-mark` через настоящий v22 control-сокет
# (production C ctlprobe) и реальные setsockopt(SO_MARK) обеих сторон.
#
# Проверяется разделение меток на живом событии SUSPECT:
#   --mark 0x2e --measure-mark 0x2f  → измерения помечены 0x2f;
#   --mark 0x2e (без --measure-mark) → измерения помечены 0x2e.
# C-сторона — собранный current d2kc, Rust — r2o-controller --serve.
set -eu

ROOT=$(CDPATH='' cd -- "$(dirname -- "$0")/.." && pwd)
D2O_ROOT=${R2O_DONOR_ROOT:?set R2O_DONOR_ROOT to the clean D2O checkout}
EXPECTED_D2O_SHA=7a5fab97a1a7f0f00ebb906dba7ed568cdc0ca05
ACTUAL_D2O_SHA=$(git -C "$D2O_ROOT" rev-parse HEAD)
CC=${CC:-cc}
CARGO=${CARGO:-cargo}
TMPDIR=${TMPDIR:-/tmp}

if [ "$ACTUAL_D2O_SHA" != "$EXPECTED_D2O_SHA" ]; then
    printf 'Expected D2O current %s, got %s\n' "$EXPECTED_D2O_SHA" "$ACTUAL_D2O_SHA" >&2
    exit 2
fi

TEMP=$(mktemp -d "$TMPDIR/r2o-measure-mark.XXXXXX")
SOCK_TMP=$(mktemp -d /tmp/r2o-measure-mark-sock.XXXXXX)
cleanup() {
    result=$?
    trap - EXIT HUP INT TERM
    if [ -n "${ctl_pid:-}" ]; then
        kill "$ctl_pid" 2>/dev/null || true
        wait "$ctl_pid" 2>/dev/null || true
    fi
    if [ -n "${ctl_fd:-}" ]; then
        exec 3>&- 2>/dev/null || true
    fi
    rm -rf -- "$TEMP" "$SOCK_TMP"
    exit "$result"
}
trap cleanup EXIT HUP INT TERM

mkdir -p "$TEMP"
cp "$ROOT/scripts/fixtures/mark_logger.c" "$TEMP/mark_logger.c"
"$CC" -shared -fPIC -O2 -o "$TEMP/libmarklogger.so" "$TEMP/mark_logger.c" -ldl

make -C "$D2O_ROOT/core" tcp1620_whitelist.inc hello_profiles.inc >/dev/null 2>&1 || true
make -C "$D2O_ROOT/datapath" clean >/dev/null 2>&1 || true
make -C "$D2O_ROOT/datapath" ctlprobe CC="$CC" >/dev/null
(
    cd "$D2O_ROOT/core"
    "$CC" -std=c99 -O2 -Iinclude -I../datapath/include -I../detect/include \
        -I../runtime -DD2K_RELEASE_ID='"dev"' -o "$TEMP/d2kc" \
        d2kc.c diagnostics.c httpsprobe.c httpsearch.c httpup_logic.c sched.c \
        quichello.c plantlv.c verdict.c meas.c crypto.c quic.c quicsnap.c \
        quicsnap_reseal.c quicwire.c quicprobe.c quicarms.c ipfrag.c net4.c \
        props.c voice.c voice_discovery.c stun.c hello.c catalog.c groups.c \
        domain.c match.c compose.c measured.c link.c volume.c tls13.c tls12.c \
        p256.c tls13core.c x25519.c verify.c verify_quic_replay.c quicconn.c \
        h3.c ../detect/bridge.c ../detect/classify.c ../detect/poison.c \
        ../detect/props.c ../detect/raw.c ../detect/trigger.c \
        ../detect/response.c ../datapath/plan_parse.c ../datapath/plan_apply.c \
        ../datapath/wire.c ../datapath/wire_udp.c udpplan.c udpruntime.c \
        ../runtime/d2k_dns_config.c -lpthread
)
"$CARGO" build --manifest-path "$ROOT/Cargo.toml" --locked --offline \
    -q -p r2o-controller --bin r2o-controller
R2O="$ROOT/target/debug/r2o-controller"
C="$TEMP/d2kc"
CTL="$D2O_ROOT/datapath/ctlprobe"

run_case() {
    impl=$1
    with_measure=$2
    expected=$3
    name=$4
    sock="$SOCK_TMP/$name.sock"
    fifo="$SOCK_TMP/$name.fifo"
    cat="$TEMP/$name.catalog.json"
    marks="$TEMP/$name.marks"
    : >"$marks"
    printf '{}' >"$cat"
    mkfifo "$fifo"
    "$CTL" "$sock" <"$fifo" >"$TEMP/$name.ctl.out" 2>"$TEMP/$name.ctl.err" &
    ctl_pid=$!
    exec 3>"$fifo"
    ctl_fd=1
    attempt=0
    while [ ! -S "$sock" ] && [ "$attempt" -lt 100 ]; do
        sleep 0.05
        attempt=$((attempt + 1))
    done
    [ -S "$sock" ] || { echo "$name: ctlprobe не поднялся" >&2; exit 1; }
    if [ "$impl" = c ]; then
        if [ "$with_measure" = yes ]; then
            measure_args="--measure-mark 0x2f"
        else
            measure_args=
        fi
        R2O_MARK_LOG="$marks" LD_PRELOAD="$TEMP/libmarklogger.so" \
            timeout 8 "$C" --control "$sock" --catalog "$cat" \
            --live "$TEMP/$name.live.json" --mark 0x2e $measure_args \
            >"$TEMP/$name.out" 2>"$TEMP/$name.err" &
        agent_pid=$!
    else
        if [ "$with_measure" = yes ]; then
            measure_args="--measure-mark 0x2f"
        else
            measure_args=
        fi
        R2O_MARK_LOG="$marks" LD_PRELOAD="$TEMP/libmarklogger.so" \
            timeout 8 "$R2O" --control-wire v22 --control-release-id dev \
            --serve "$sock" "$cat" --discover --mark 0x2e $measure_args \
            >"$TEMP/$name.out" 2>"$TEMP/$name.err" &
        agent_pid=$!
    fi
    sleep 1
    echo 'hello example.com' >&3
    echo 'rst' >&3
    sleep 6
    kill "$agent_pid" 2>/dev/null || true
    wait "$agent_pid" 2>/dev/null || true
    echo quit >&3 2>/dev/null || true
    exec 3>&-
    ctl_fd=
    kill "$ctl_pid" 2>/dev/null || true
    wait "$ctl_pid" 2>/dev/null || true
    ctl_pid=
    if ! grep -qx "$expected" "$marks"; then
        echo "$name: нет SO_MARK $expected в журнале;" >&2
        sort -n "$marks" | uniq -c >&2
        cat "$TEMP/$name.err" >&2 || true
        exit 1
    fi
    other=46
    [ "$expected" = 46 ] && other=47
    if grep -qx "$other" "$marks"; then
        echo "$name: неожиданная метка $other вместе с $expected" >&2
        sort -n "$marks" | uniq -c >&2
        exit 1
    fi
}

run_case c yes 47 c-measure
run_case c no 46 c-fallback
run_case rust yes 47 rust-measure
run_case rust no 46 rust-fallback

printf 'PASS: C/Rust CLI --measure-mark split through v22 ctlprobe (D2O %s)\n' \
    "$ACTUAL_D2O_SHA"
