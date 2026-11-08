#!/bin/sh
# M5: paired C/Rust differential volume RX (partial/pair/repeat/evidence).
set -eu

ROOT=$(CDPATH='' cd -- "$(dirname -- "$0")/.." && pwd)
D2O_ROOT=${R2O_DONOR_ROOT:?set R2O_DONOR_ROOT to the pinned D2O checkout}
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
TEMP=$(mktemp -d "$TMPDIR/r2o-m5-volume.XXXXXX")
trap 'rm -rf -- "$TEMP"' EXIT HUP INT TERM

"$CC" -std=c99 -O2 -Wall -Wextra -Werror \
    -ffunction-sections -fdata-sections \
    -I"$D2O_ROOT/core" -I"$D2O_ROOT/core/include" -I"$D2O_ROOT/datapath/include" \
    -o "$TEMP/d2o-volume-rx" \
    "$ROOT/crates/r2o-controller/tests/d2o_volume_rx_differential.c" \
    -Wl,--gc-sections
"$TEMP/d2o-volume-rx" >"$TEMP/c.out"

"$CARGO" run --manifest-path "$ROOT/Cargo.toml" --locked --offline \
    -q -p r2o-controller --example m5_volume_trace >"$TEMP/rust.out"

if ! diff -u "$TEMP/c.out" "$TEMP/rust.out"; then
    printf 'FAIL: volume RX differential\n' >&2
    exit 1
fi

printf 'cases=%s\n' "$(grep -c '^case ' "$TEMP/c.out")"
grep -A2 '^case evidence-body$' "$TEMP/c.out"
printf 'PASS: C/Rust volume RX verdicts match (D2O %s)\n' "$ACTUAL_D2O_SHA"
