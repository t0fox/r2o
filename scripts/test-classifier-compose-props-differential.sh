#!/bin/sh
# C/Rust differential: detect/props.c prop_probes/apply_set/compose_from_props.
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
TEMP=$(mktemp -d "$TMPDIR/r2o-compose-props.XXXXXX")
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
    -o "$TEMP/d2o-compose-props" \
    "$ROOT/crates/r2o-controller/tests/d2o_compose_props_differential.c" \
    -Wl,--gc-sections
"$TEMP/d2o-compose-props" >"$TEMP/c.out"

R2O_COMPOSE_PROPS_OUTPUT="$TEMP/rust.out" \
    "$CARGO" test --manifest-path "$ROOT/Cargo.toml" --locked --offline \
    -p r2o-controller --lib \
    raw_probe::tests::d2o_props_compose_differential_matches_c \
    -- --exact >"$TEMP/cargo.log" 2>&1

if ! diff -u "$TEMP/c.out" "$TEMP/rust.out"; then
    printf 'FAIL: compose/props differential\n' >&2
    exit 1
fi

cat "$TEMP/c.out"
printf 'cases=%s\n' "$(grep -c '^prop|\|^apply|\|^compose|' "$TEMP/c.out")"
printf 'PASS: C/Rust prop probes, apply_set and compose_from_props match (D2O %s)\n' \
    "$ACTUAL_D2O_SHA"
