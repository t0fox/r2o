#!/bin/sh
# C/Rust differential: remember/recall (core/sched.c:1841-1869), кольцо 512.
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
TEMP=$(mktemp -d "$TMPDIR/r2o-remember-recall.XXXXXX")
trap 'rm -rf -- "$TEMP"' EXIT HUP INT TERM

"$CC" -std=gnu11 -O2 -ffunction-sections -fdata-sections \
    -I"$D2O_ROOT/core" -I"$D2O_ROOT/core/include" -I"$D2O_ROOT/datapath/include" \
    -o "$TEMP/d2o-recall" \
    "$ROOT/crates/r2o-controller/tests/d2o_remember_recall_differential.c" \
    "$D2O_ROOT/core/groups.c" "$D2O_ROOT/core/domain.c" \
    -Wl,--gc-sections -lpthread -lm
"$TEMP/d2o-recall" >"$TEMP/c.out"

R2O_REMEMBER_RECALL_DIFF_OUTPUT="$TEMP/rust.out" \
    "$CARGO" test --manifest-path "$ROOT/Cargo.toml" --locked --offline \
    -p r2o-controller --bin r2o-controller tests::remember_recall_differential_matches_c \
    -- --exact >"$TEMP/cargo.log" 2>&1

diff -u "$TEMP/c.out" "$TEMP/rust.out"
printf 'cases=%s\n' "$(grep -c '=' "$TEMP/c.out")"
printf 'PASS: remember/recall C/Rust match (D2O %s)\n' "$ACTUAL_D2O_SHA"
