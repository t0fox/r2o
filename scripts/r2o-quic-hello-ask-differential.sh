#!/bin/sh
# C/Rust differential: `d2k_quic_hello_ask`/`d2k_quic_hello_split`
# (core/quichello.c:330-437): PLAIN/V2/SPLIT/LONGER/CLEAR_FIXED и две датаграммы.
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
TEMP=$(mktemp -d "$TMPDIR/r2o-quic-ask.XXXXXX")
trap 'rm -rf -- "$TEMP"' EXIT HUP INT TERM

clang-18 -std=gnu11 -O2 -Wall -Wextra -Werror \
    -Wno-unused-function -Wno-unused-variable \
    -ffunction-sections -fdata-sections \
    -I"$CORE" -I"$CORE/include" \
    -DD2K_RELEASE_ID='"dev"' \
    "$ROOT/crates/r2o-controller/tests/d2o_quic_hello_ask_differential.c" \
    "$CORE/quichello.c" "$CORE/quicwire.c" "$CORE/crypto.c" \
    "$CORE/quic.c" "$CORE/quicsnap.c" \
    "$CORE/hello.c" "$CORE/tls13core.c" "$CORE/x25519.c" \
    -Wl,--gc-sections -lpthread -lm -o "$TEMP/c"

R2O_QUIC_ASK_SAMPLE="$TEMP/sample.hex" "$TEMP/c" >"$TEMP/c.out"
R2O_QUIC_ASK_SAMPLE="$TEMP/sample.hex" \
    R2O_QUIC_ASK_OUTPUT="$TEMP/rust.out" \
    cargo test --locked -p r2k-core --lib \
    quic::tests::quic_hello_ask_matches_c -- --exact \
    >"$TEMP/rust.log" 2>&1 || {
        cat "$TEMP/rust.log" >&2
        exit 1
    }
diff -u "$TEMP/c.out" "$TEMP/rust.out"
printf 'PASS: d2k_quic_hello_ask/split matches C (%s, %s cases)\n' \
    "$ACTUAL_SHA" "$(wc -l <"$TEMP/c.out" | tr -d ' ')"
