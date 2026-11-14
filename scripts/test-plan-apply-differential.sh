#!/bin/sh
# C/Rust differential: d2k_plan_apply on simple plans (a378).
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
TEMP=$(mktemp -d "$TMPDIR/r2o-plan-apply.XXXXXX")
trap 'rm -rf -- "$TEMP"' EXIT HUP INT TERM

"$CC" -std=c99 -D_GNU_SOURCE -O2 -Wall -Wextra -Werror \
    -I"$D2O_ROOT/datapath/include" -I"$D2O_ROOT/core/include" \
    -ffunction-sections -fdata-sections \
    -o "$TEMP/d2o-plan-apply" \
    "$ROOT/crates/r2k-core/tests/d2o_plan_apply_differential.c" \
    "$D2O_ROOT/datapath/plan_parse.c" "$D2O_ROOT/datapath/plan_apply.c" \
    "$D2O_ROOT/core/plantlv.c" "$D2O_ROOT/core/quic.c" \
    "$D2O_ROOT/core/quicwire.c" "$D2O_ROOT/core/crypto.c" \
    -Wl,--gc-sections

: >"$TEMP/c.out"
mkdir -p "$TEMP/fixtures"
for plan in "$ROOT"/crates/r2k-core/tests/fixtures/plan_apply/*.plan; do
    name=$(basename "$plan" .plan)
    "$TEMP/d2o-plan-apply" "$plan" "$TEMP/fixtures/$name.tlv" >>"$TEMP/c.out"
done

R2O_PLAN_APPLY_FIXTURES="$TEMP/fixtures" \
R2O_PLAN_APPLY_DIFF_OUTPUT="$TEMP/rust.out" \
    "$CARGO" test --manifest-path "$ROOT/Cargo.toml" --locked --offline \
    -p r2k-core --test apply plan_apply_differential_matches_c \
    -- --exact >"$TEMP/cargo.log" 2>&1

diff -u "$TEMP/c.out" "$TEMP/rust.out"
printf 'cases=%s\n' "$(grep -c '^case ' "$TEMP/c.out")"
printf 'PASS: d2k_plan_apply simple plans C/Rust match (D2O %s)\n' "$ACTUAL_D2O_SHA"
