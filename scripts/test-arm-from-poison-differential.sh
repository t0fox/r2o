#!/bin/sh
# C/Rust field-by-field differential: d2k_arm_from_poison -> d2k_arm fields.
set -eu

ROOT=$(CDPATH='' cd -- "$(dirname -- "$0")/.." && pwd)
D2O_ROOT=${R2O_DONOR_ROOT:?set R2O_DONOR_ROOT to the pinned D2O checkout}
EXPECTED_D2O_SHA=${R2O_EXPECTED_DONOR_SHA:-a378e230947ebfd011439e1cac0f1e994d883aae}
ACTUAL_D2O_SHA=$(git -C "$D2O_ROOT" rev-parse HEAD)
CC=${CC:-cc}
CARGO=${CARGO:-cargo}
TMPDIR=${TMPDIR:-"${ROOT%/r2o}/r2o-tooling/tmp"}

if [ "$ACTUAL_D2O_SHA" != "$EXPECTED_D2O_SHA" ]; then
    printf 'Expected D2O %s, got %s\n' "$EXPECTED_D2O_SHA" "$ACTUAL_D2O_SHA" >&2
    exit 2
fi

mkdir -p "$TMPDIR"
TEMP=$(mktemp -d "$TMPDIR/r2o-arm-from-poison.XXXXXX")
cleanup() {
    status=$?
    rm -rf -- "$TEMP"
    exit "$status"
}
trap cleanup EXIT HUP INT TERM

"$CC" -std=gnu11 -O2 -Wall -Wextra -Werror \
    -ffunction-sections -fdata-sections \
    -I"$D2O_ROOT/detect" -I"$D2O_ROOT/detect/include" \
    -I"$D2O_ROOT/core/include" -I"$D2O_ROOT/datapath/include" \
    -o "$TEMP/d2o-arm-from-poison" \
    "$ROOT/crates/r2o-controller/tests/d2o_arm_from_poison_differential.c" \
    -Wl,--gc-sections
"$TEMP/d2o-arm-from-poison" >"$TEMP/c.out"

R2O_ARM_FROM_POISON_OUTPUT="$TEMP/rust.out" \
    "$CARGO" test --manifest-path "$ROOT/Cargo.toml" --locked --offline \
    -p r2o-controller --lib \
    classify::probes_word_tests::d2o_arm_from_poison_differential_matches_c \
    -- --exact >"$TEMP/cargo.log" 2>&1

if ! diff -u "$TEMP/c.out" "$TEMP/rust.out"; then
    printf 'FAIL: arm_from_poison differential\n' >&2
    exit 1
fi

cat "$TEMP/c.out"
printf 'cases=%s\n' "$(grep -c '^arm|' "$TEMP/c.out")"
printf 'PASS: C/Rust d2k_arm fields match (D2O %s)\n' "$ACTUAL_D2O_SHA"
