#!/bin/sh
# C/Rust differential: `d2k_quic_hello_incomplete` (core/quic.c:672-685).
set -eu

ROOT=$(CDPATH='' cd -- "$(dirname -- "$0")/.." && pwd)
DONOR=${R2O_DONOR_ROOT:-/mnt/e/d2o-current}
EXPECTED_SHA=7a5fab97a1a7f0f00ebb906dba7ed568cdc0ca05
ACTUAL_SHA=$(git -C "$DONOR" rev-parse HEAD)
[ "$ACTUAL_SHA" = "$EXPECTED_SHA" ] || {
    printf 'Expected D2O %s, got %s\n' "$EXPECTED_SHA" "$ACTUAL_SHA" >&2
    exit 2
}
CORE="$DONOR/core"
TMPDIR=${TMPDIR:-/tmp}
TEMP=$(mktemp -d "$TMPDIR/r2o-quic-incomplete.XXXXXX")
trap 'rm -rf -- "$TEMP"' EXIT HUP INT TERM

clang-18 -std=gnu11 -O2 -Wall -Wextra -Werror \
    -ffunction-sections -fdata-sections \
    -I"$CORE" -I"$CORE/include" \
    "$ROOT/crates/r2o-controller/tests/d2o_quic_hello_incomplete_differential.c" \
    "$CORE/quic.c" "$CORE/quicwire.c" "$CORE/quicsnap.c" "$CORE/crypto.c" \
    -Wl,--gc-sections -lpthread -lm -o "$TEMP/c"

R2O_QUIC_INCOMPLETE_INPUT="$TEMP/packets.hex" "$TEMP/c" >"$TEMP/c.out"
R2O_QUIC_INCOMPLETE_INPUT="$TEMP/packets.hex" \
    R2O_QUIC_INCOMPLETE_OUTPUT="$TEMP/rust.out" \
    cargo test --locked -p r2k-core --lib \
    quic::tests::hello_incomplete_matches_c -- --exact \
    >"$TEMP/rust.log" 2>&1 || {
        cat "$TEMP/rust.log" >&2
        exit 1
    }
diff -u "$TEMP/c.out" "$TEMP/rust.out"
printf 'PASS: d2k_quic_hello_incomplete matches C (%s, %s cases)\n' \
    "$ACTUAL_SHA" "$(wc -l <"$TEMP/c.out" | tr -d ' ')"
