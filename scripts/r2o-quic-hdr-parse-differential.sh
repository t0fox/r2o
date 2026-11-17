#!/bin/sh
# C/Rust differential: `d2k_qw_hdr_parse` Initial v1/v2 (core/quicwire.c:204-273).
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
TEMP=$(mktemp -d "$TMPDIR/r2o-quic-hdr-parse.XXXXXX")
trap 'rm -rf -- "$TEMP"' EXIT HUP INT TERM

clang-18 -std=gnu11 -O2 -Wall -Wextra -Werror \
    -ffunction-sections -fdata-sections \
    -I"$CORE/include" \
    "$ROOT/crates/r2o-controller/tests/d2o_quic_hdr_parse_differential.c" \
    "$CORE/quicwire.c" "$CORE/crypto.c" \
    -Wl,--gc-sections -lpthread -lm -o "$TEMP/c"

"$TEMP/c" >"$TEMP/c.out"
R2O_QUIC_HDR_PARSE_INPUT="$TEMP/c.out" \
    cargo test --locked -p r2k-core --lib \
    quic::tests::quic_hdr_parse_matches_c -- --exact --nocapture \
    >"$TEMP/rust.out" 2>"$TEMP/rust.log" || {
        cat "$TEMP/rust.log" >&2
        exit 1
    }
# cargo test печатает только вывод теста; убираем служебные строки.
grep '^[a-z0-9].*,' "$TEMP/rust.out" >"$TEMP/rust.clean" || true
diff -u "$TEMP/c.out" "$TEMP/rust.clean"
printf 'PASS: d2k_qw_hdr_parse matches C (%s, %s cases)\n' \
    "$ACTUAL_SHA" "$(wc -l <"$TEMP/c.out" | tr -d ' ')"
