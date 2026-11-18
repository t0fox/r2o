#!/bin/sh
# C/Rust differential X25519: production C-функции против независимой
# Rust-реализации (x25519-dalek), 8 скаляров и все пары.
set -eu
ROOT=$(CDPATH='' cd -- "$(dirname -- "$0")/.." && pwd)
DONOR=${R2O_DONOR_ROOT:-/mnt/e/d2o-current}
EXPECTED_SHA=7a5fab97a1a7f0f00ebb906dba7ed568cdc0ca05
ACTUAL_SHA=$(git -C "$DONOR" rev-parse HEAD)
[ "$ACTUAL_SHA" = "$EXPECTED_SHA" ] || {
    printf 'Expected D2O %s, got %s\n' "$EXPECTED_SHA" "$ACTUAL_SHA" >&2
    exit 2
}
TMP=$(mktemp -d)
trap 'rm -rf "$TMP"' EXIT HUP INT TERM
CC=${CC:-cc}
"$CC" -I "$DONOR/core/include" -o "$TMP/c" \
    "$ROOT/crates/r2k-core/tests/d2o_x25519_differential.c" \
    "$DONOR/core/x25519.c"
cargo build --locked -q -p r2k-core --example x25519_trace
"$TMP/c" > "$TMP/c.out"
"$ROOT/target/debug/examples/x25519_trace" > "$TMP/r.out"
diff -u "$TMP/c.out" "$TMP/r.out"
printf 'PASS: X25519 C/Rust vectors match (%s lines, D2O %s)\n' \
    "$(wc -l < "$TMP/c.out" | tr -d ' ')" "$ACTUAL_SHA"
