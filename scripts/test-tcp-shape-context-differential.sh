#!/bin/sh
# D20: C/Rust differential для TCP shape contexts 8–13.
# C-оракул — production inline-функции D2O `core/include/d2k_link.h`;
# Rust — production-функции `r2k_core::control`.
set -eu

ROOT=$(CDPATH='' cd -P "$(dirname "$0")/.." && pwd)
D2O_ROOT=${R2O_DONOR_ROOT:?set R2O_DONOR_ROOT to the clean D2O checkout}
EXPECTED_D2O_SHA=a378e230947ebfd011439e1cac0f1e994d883aae
ACTUAL_D2O_SHA=$(git -C "$D2O_ROOT" rev-parse HEAD)
CC=${CC:-cc}
CARGO=${CARGO:-cargo}
TMPDIR=${TMPDIR:-"${ROOT%/r2o}/r2o-tooling/tmp"}

if [ "$ACTUAL_D2O_SHA" != "$EXPECTED_D2O_SHA" ]; then
    printf 'Expected D2O %s, got %s\n' "$EXPECTED_D2O_SHA" "$ACTUAL_D2O_SHA" >&2
    exit 2
fi

mkdir -p "$TMPDIR"
TEMP=$(mktemp -d "$TMPDIR/r2o-tcp-shape.XXXXXX")
trap 'rm -rf -- "$TEMP"' EXIT HUP INT TERM

"$CC" -std=c11 -O2 -I "$D2O_ROOT" -I "$D2O_ROOT/core/include" \
    -I "$D2O_ROOT/datapath/include" -I "$D2O_ROOT/runtime" \
    "$ROOT/scripts/fixtures/tcp_shape_table.c" -o "$TEMP/c-oracle"
"$TEMP/c-oracle" > "$TEMP/c.txt"

"$CARGO" run --manifest-path "$ROOT/Cargo.toml" --locked --offline \
    --package r2k-core --example tcp_shape_table > "$TEMP/rust.txt"

if ! diff -u "$TEMP/c.txt" "$TEMP/rust.txt"; then
    printf 'FAIL: TCP shape context C/Rust differential\n' >&2
    exit 1
fi

printf 'PASS: TCP shape contexts 0-15 match D2O %s\n' "$ACTUAL_D2O_SHA"
