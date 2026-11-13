#!/bin/sh
# C/Rust differential: d2k_arm_plan (core/compose.c:1552-1751) для
# произвольных наборов полей, включая tcpts/ipidzero/disorder_pos.
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
TEMP=$(mktemp -d "$TMPDIR/r2o-arm-plan.XXXXXX")
trap 'rm -rf -- "$TEMP"' EXIT HUP INT TERM

"$CC" -std=gnu11 -O2 -ffunction-sections -fdata-sections \
    -I"$D2O_ROOT/core/include" -I"$D2O_ROOT/datapath/include" \
    -o "$TEMP/d2o-arm-plan" \
    "$ROOT/crates/r2o-controller/tests/d2o_arm_plan_differential.c" \
    "$D2O_ROOT/core/compose.c" "$D2O_ROOT/core/hello.c" \
    -Wl,--gc-sections
"$TEMP/d2o-arm-plan" >"$TEMP/c.out"

R2O_ARM_PLAN_DIFF_OUTPUT="$TEMP/rust.out" \
    "$CARGO" test --manifest-path "$ROOT/Cargo.toml" --locked --offline \
    -p r2o-controller --lib \
    r2o_fallback::tests::arm_plan_arbitrary_combinations_match_donor \
    -- --exact >"$TEMP/cargo.log" 2>&1

diff -u "$TEMP/c.out" "$TEMP/rust.out"
printf 'cases=%s\n' "$(grep -c '^case ' "$TEMP/c.out")"
printf 'PASS: arm_plan arbitrary combinations match (D2O %s)\n' "$ACTUAL_D2O_SHA"
