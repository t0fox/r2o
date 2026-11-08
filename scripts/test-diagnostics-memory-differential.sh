#!/bin/sh
# S11: paired C/Rust differential allocator sites и madvise.
set -eu

ROOT=$(CDPATH='' cd -- "$(dirname -- "$0")/.." && pwd)
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
TEMP=$(mktemp -d "$TMPDIR/r2o-diagnostics-memory.XXXXXX")
trap 'rm -rf -- "$TEMP"' EXIT HUP INT TERM

"$CC" -std=c11 -O2 -Wall -Wextra \
    -I"$D2O_ROOT/core/include" -DD2K_RELEASE_ID='"dev"' \
    -o "$TEMP/c-memory" "$ROOT/scripts/fixtures/d2o_diagnostics_memory_trace.c" \
    "$D2O_ROOT/core/diagnostics.c"
"$TEMP/c-memory" > "$TEMP/c.out"

"$CARGO" run --manifest-path "$ROOT/Cargo.toml" --locked --offline \
    -p r2o-controller --example diagnostics_memory_trace > "$TEMP/rust.out"

if ! diff -u "$TEMP/c.out" "$TEMP/rust.out"; then
    printf 'FAIL: diagnostics allocator/madvise differential\n' >&2
    exit 1
fi

"$CARGO" test --manifest-path "$ROOT/Cargo.toml" --locked --offline \
    -p r2o-controller --lib memory_tracking_and_madvise_json_match_d2o_shape
printf 'PASS: C and Rust diagnostics allocator sites and madvise counters match (D2O %s)\n' "$ACTUAL_D2O_SHA"
