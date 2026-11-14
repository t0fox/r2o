#!/bin/sh
# C/Rust differential: release_original callback (hold flush и mismatch).
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

make -s -C "$D2O_ROOT/datapath" hold.o capture.o track.o http80.o wire.o \
    core_httpup_logic.o >/dev/null
mkdir -p "$TMPDIR"
TEMP=$(mktemp -d "$TMPDIR/r2o-release-original.XXXXXX")
trap 'rm -rf -- "$TEMP"' EXIT HUP INT TERM

"$CC" -std=c99 -O2 -Wall -Wextra -Werror \
    -I"$D2O_ROOT/datapath/include" -I"$D2O_ROOT/core/include" \
    -o "$TEMP/d2o-release-original" \
    "$ROOT/crates/r2o-datapath/tests/d2o_release_original_differential.c" \
    "$D2O_ROOT/datapath/hold.o" \
    "$D2O_ROOT/datapath/capture.o" \
    "$D2O_ROOT/datapath/track.o" \
    "$D2O_ROOT/datapath/http80.o" \
    "$D2O_ROOT/datapath/wire.o" \
    "$D2O_ROOT/datapath/core_httpup_logic.o"
"$TEMP/d2o-release-original" >"$TEMP/c.out"

R2O_RELEASE_ORIGINAL_DIFF_OUTPUT="$TEMP/rust.out" \
    "$CARGO" test --manifest-path "$ROOT/Cargo.toml" --locked --offline \
    -p r2o-datapath --lib hold::tests::release_original_trace \
    -- --ignored --nocapture >"$TEMP/cargo.log" 2>&1

if ! diff -u "$TEMP/c.out" "$TEMP/rust.out"; then
    printf 'FAIL: release_original differential\n' >&2
    exit 1
fi

printf 'cases=%s\n' "$(grep -c '^obs ' "$TEMP/c.out")"
printf 'PASS: C/Rust release_original callback match (D2O %s)\n' "$ACTUAL_D2O_SHA"
