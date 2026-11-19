#!/bin/sh
# C/Rust differential: qp_send_one, qp_arm_first_send, qp_send_fragmented.
#
# C-сторона включает production core/quicprobe.c и mock-I/O из
# core/test_udp_runtime.c: socket/connect/bind/close/setsockopt/send
# перехвачены в том же TU, QUIC handshake и root не нужны. Rust-сторона —
# production QuicReplayProbe::run_with_plan / r2o_udp_plan_send_with_sink.
#
# Кейсы: plain, tail, ttl, split, arm-ttl, refused, frag1.
set -eu

ROOT=$(CDPATH='' cd -- "$(dirname -- "$0")/.." && pwd)
D2O_ROOT=${R2O_DONOR_ROOT:-/mnt/e/d2o-a378w}
EXPECTED_D2O_SHA=7a5fab97a1a7f0f00ebb906dba7ed568cdc0ca05
ACTUAL_D2O_SHA=$(git -C "$D2O_ROOT" rev-parse HEAD)
if [ "$ACTUAL_D2O_SHA" != "$EXPECTED_D2O_SHA" ]; then
    printf 'Expected D2O %s, got %s\n' "$EXPECTED_D2O_SHA" "$ACTUAL_D2O_SHA" >&2
    exit 2
fi

CC=${CC:-gcc}
CARGO=${CARGO:-cargo}
PYTHON=${PYTHON:-python3}
for tool in "$CC" "$CARGO" "$PYTHON"; do
    command -v "$tool" >/dev/null 2>&1 || {
        printf 'missing required command: %s\n' "$tool" >&2
        exit 127
    }
done

TMPDIR=${TMPDIR:-/tmp}
TEMP=$(mktemp -d "$TMPDIR/r2o-quic-send-one.XXXXXX")
trap 'rm -rf -- "$TEMP"' EXIT HUP INT TERM

# Объекты и libd2k_udp.a — те же, что у core/Makefile test_quic_sink.
if ! make -C "$D2O_ROOT/core" CC="$CC" \
    libd2k_udp.a quicsnap.o quicsnap_reseal.o quicarms.o quichello.o \
    hello.o tls13core.o x25519.o meas.o quicconn.o h3.o net4.o props.o \
    diagnostics.o >"$TEMP/d2o-build.log" 2>&1; then
    cat "$TEMP/d2o-build.log" >&2
    exit 1
fi

(
    cd "$D2O_ROOT/core"
    if ! "$CC" -std=c99 -O2 -Wall -Wextra -Werror \
        -I. -Iinclude -I../core/include -I../datapath/include \
        -DD2K_RELEASE_ID='"dev"' -o "$TEMP/c" \
        "$ROOT/crates/r2o-controller/tests/d2o_quic_send_one_differential.c" \
        httpup_logic.c ../datapath/http80.c ../datapath/hold.c \
        ../datapath/capture.c ../datapath/nat.c ../datapath/ctq.c \
        ../datapath/nl.c ../datapath/track.c ../datapath/tls.c \
        ../datapath/journal.c ../datapath/plans.c ../core/stun.c \
        quicsnap.o quicsnap_reseal.o quicarms.o quichello.o hello.o \
        tls13core.o x25519.o meas.o quicconn.o h3.o net4.o props.o \
        diagnostics.o libd2k_udp.a -lpthread >"$TEMP/c-build.log" 2>&1; then
        cat "$TEMP/c-build.log" >&2
        exit 1
    fi
)

# Rust-тест сначала пишет для каждого кейса QSN-снимок и свой trace.
if ! R2O_QUIC_SEND_ONE_DIR="$TEMP" "$CARGO" test \
    --manifest-path "$ROOT/Cargo.toml" --locked --offline \
    -p r2o-controller --lib \
    quic_replay::tests::quic_send_one_c_differential_harness \
    -- --exact >"$TEMP/rust.log" 2>&1; then
    cat "$TEMP/rust.log" >&2
    exit 1
fi

CASES='plain tail ttl split arm-ttl refused frag1 frag2 frag3 frag4'
CASES_COUNT=0
for name in $CASES; do
    if ! R2O_QUIC_SEND_ONE_FRAG_META="$TEMP/$name.meta" \
        "$TEMP/c" "$name" "$TEMP/$name.qsn" >"$TEMP/$name.c"; then
        printf 'FAIL: C fixture %s\n' "$name" >&2
        exit 1
    fi
    case $name in
    frag[1-4])
        "$PYTHON" "$ROOT/scripts/r2o-quic-send-one-frag-normalize.py" \
            <"$TEMP/$name.rust" >"$TEMP/$name.rust.norm"
        "$PYTHON" "$ROOT/scripts/r2o-quic-send-one-frag-normalize.py" \
            <"$TEMP/$name.c" >"$TEMP/$name.c.norm"
        if ! diff -u "$TEMP/$name.rust.norm" "$TEMP/$name.c.norm"; then
            printf 'FAIL: qp_send_fragmented differential %s\n' "$name" >&2
            exit 1
        fi
        ;;
    *)
        if ! diff -u "$TEMP/$name.rust" "$TEMP/$name.c"; then
            printf 'FAIL: qp_send_one differential %s\n' "$name" >&2
            exit 1
        fi
        ;;
    esac
    CASES_COUNT=$((CASES_COUNT + 1))
    printf 'case %s: PASS\n' "$name"
done

printf 'PASS: qp_send_one/qp_arm_first_send/qp_send_fragmented C/Rust match (%d cases, D2O %s).\n' \
    "$CASES_COUNT" "$ACTUAL_D2O_SHA"
