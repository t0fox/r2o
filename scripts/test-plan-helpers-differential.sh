#!/bin/sh
# C/Rust differential: plan helpers wr16/wr24/cmp_size.
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
TEMP=$(mktemp -d "$TMPDIR/r2o-plan-helpers.XXXXXX")
trap 'rm -rf -- "$TEMP"' EXIT HUP INT TERM

"$CC" -std=c99 -O2 -Wall -Wextra -Werror -ffunction-sections -fdata-sections \
    -I"$D2O_ROOT/datapath/include" -I"$D2O_ROOT/core/include" \
    -I"$D2O_ROOT/datapath" \
    -o "$TEMP/d2o-plan-helpers" \
    "$ROOT/crates/r2o-datapath/tests/d2o_plan_helpers_differential.c" \
    -Wl,--gc-sections
"$TEMP/d2o-plan-helpers" >"$TEMP/c.out"

R2O_PLAN_HELPERS_DIFF_OUTPUT="$TEMP/rust.out" \
    "$CARGO" test --manifest-path "$ROOT/Cargo.toml" --locked --offline \
    -p r2k-core --lib plan::apply::helper_differential_tests::plan_helper_differential_matches_c \
    -- --ignored >"$TEMP/cargo.log" 2>&1

if ! diff -u "$TEMP/c.out" "$TEMP/rust.out"; then
    printf 'FAIL: plan helpers differential\n' >&2
    exit 1
fi

printf 'cases=%s\n' "$(wc -l <"$TEMP/c.out")"
printf 'PASS: plan helpers wr16/wr24/cmp_size C/Rust match (D2O %s)\n' "$ACTUAL_D2O_SHA"
