#!/bin/sh
# C/Rust differential полного текста измеренного плана:
# d2k_arm_from_poison + d2k_arm_plan_measured_cap против production
# measured_plan_text, send_cap 1/72/1280/1400/1500/65535, decoy empty/full.
set -eu

ROOT=$(CDPATH='' cd -- "$(dirname -- "$0")/.." && pwd)
D2O_ROOT=${R2O_DONOR_ROOT:?set R2O_DONOR_ROOT}
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
TEMP=$(mktemp -d "$TMPDIR/r2o-plan-measured.XXXXXX")
trap 'rm -rf -- "$TEMP"' EXIT HUP INT TERM

INCLUDES="-I$D2O_ROOT/detect -I$D2O_ROOT/core -I$D2O_ROOT/detect/include -I$D2O_ROOT/core/include -I$D2O_ROOT/datapath/include"
# poison.c и measured.c определяют одноимённые static append_fmt/append_hex,
# поэтому это две единицы трансляции.
"$CC" -std=gnu11 -O2 -Wall -Wextra -Werror \
    -ffunction-sections -fdata-sections $INCLUDES \
    -c -o "$TEMP/plan-main.o" \
    "$ROOT/crates/r2o-controller/tests/d2o_plan_measured_cap_differential.c"
"$CC" -std=gnu11 -O2 -Wall -Wextra -Werror \
    -ffunction-sections -fdata-sections $INCLUDES \
    -c -o "$TEMP/plan-arm.o" \
    "$ROOT/crates/r2o-controller/tests/d2o_plan_measured_arm_support.c"
"$CC" -o "$TEMP/d2o-plan-measured" "$TEMP/plan-main.o" "$TEMP/plan-arm.o" \
    -Wl,--gc-sections
"$TEMP/d2o-plan-measured" >"$TEMP/c.out"

R2O_PLAN_MEASURED_OUTPUT="$TEMP/rust.out" \
    "$CARGO" test --manifest-path "$ROOT/Cargo.toml" --locked --offline \
    -p r2o-controller --test measured_plan \
    d2o_arm_plan_measured_cap_differential_matches_c \
    -- --exact --ignored >"$TEMP/cargo.log" 2>&1

if ! diff -u "$TEMP/c.out" "$TEMP/rust.out"; then
    printf 'FAIL: full measured-plan differential\n' >&2
    exit 1
fi
cases=$(grep -c '^plan|' "$TEMP/c.out")
cat "$TEMP/c.out"
printf 'PASS: C/Rust full measured plan match (%s cases, D2O %s)\n' \
    "$cases" "$ACTUAL_D2O_SHA"
