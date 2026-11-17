#!/bin/sh
# C/Rust differential: `put16`/`get16` из core/tls13.c и core/tls13core.c.
# Одна и та же пара функций в двух TLS-файлах; Rust использует
# `u16::to_be_bytes`/`from_be_bytes`.
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
TEMP=$(mktemp -d "$TMPDIR/r2o-tls13-put16.XXXXXX")
trap 'rm -rf -- "$TEMP"' EXIT HUP INT TERM

for source in tls13.c tls13core.c; do
    clang-18 -std=gnu11 -O2 -Wall -Wextra -Werror \
        -Wno-unused-function -Wno-unused-variable \
        -ffunction-sections -fdata-sections \
        -I"$CORE" -I"$CORE/include" \
        -I"$DONOR/datapath/include" -I"$DONOR/runtime" \
        -DD2K_RELEASE_ID='"dev"' -DTLS_SOURCE="\"$source\"" \
        "$ROOT/crates/r2o-controller/tests/d2o_tls13_put16_get16_differential.c" \
        -Wl,--gc-sections -lpthread -lm -o "$TEMP/$source.bin"
    "$TEMP/$source.bin" >"$TEMP/$source.out"
done

R2O_TLS13_PUT16_DIFF_OUTPUT="$TEMP/rust.out" \
    cargo test --locked -p r2o-controller --lib \
    tls12::tls13_put16_get16_tests::tls13_put16_get16_match_c -- --exact \
    >"$TEMP/rust.log" 2>&1 || {
        cat "$TEMP/rust.log" >&2
        exit 1
    }

for source in tls13.c tls13core.c; do
    diff -u "$TEMP/$source.out" "$TEMP/rust.out"
    printf 'PASS: %s put16/get16 matches C for all 65536 values\n' "$source"
done
printf 'PASS: TLS 1.3 big-endian u16 helpers match C (%s)\n' "$ACTUAL_SHA"
