#!/bin/sh
# CL15: paired C/Rust differential d2k_compose (d2k-plan text).
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
TEMP=$(mktemp -d "$TMPDIR/r2o-cl15-compose.XXXXXX")
trap 'rm -rf -- "$TEMP"' EXIT HUP INT TERM

make -C "$D2O_ROOT/core" compose.o measured.o hello.o meas.o link.o diagnostics.o >/dev/null
"$CC" -std=c99 -O2 -Wall -Wextra -Werror \
    -I"$D2O_ROOT/core" -I"$D2O_ROOT/core/include" -I"$D2O_ROOT/datapath/include" \
    -o "$TEMP/d2o-compose" \
    "$ROOT/crates/r2o-controller/tests/d2o_compose_differential.c" \
    "$D2O_ROOT/core/compose.o" \
    "$D2O_ROOT/core/measured.o" \
    "$D2O_ROOT/core/hello.o" \
    "$D2O_ROOT/core/meas.o" \
    "$D2O_ROOT/core/link.o" \
    "$D2O_ROOT/core/diagnostics.o" \
    -lpthread
"$TEMP/d2o-compose" >"$TEMP/c.out"

"$CARGO" run --manifest-path "$ROOT/Cargo.toml" --locked --offline \
    -q -p r2o-controller --example cl15_compose_trace >"$TEMP/rust.out"

if ! diff -u "$TEMP/c.out" "$TEMP/rust.out"; then
    printf 'FAIL: compose differential\n' >&2
    exit 1
fi

printf 'cases=%s\n' "$(grep -c '^case ' "$TEMP/c.out")"
grep -A3 '^case all-mixed$' "$TEMP/c.out" | head -5
printf 'PASS: C/Rust d2k_compose texts match (D2O %s)\n' "$ACTUAL_D2O_SHA"
