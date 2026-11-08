#!/bin/sh
# D21: paired C/Rust differential ядра очереди отложенной отправки.
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
TEMP=$(mktemp -d "$TMPDIR/r2o-d21-sched.XXXXXX")
trap 'rm -rf -- "$TEMP"' EXIT HUP INT TERM

"$CC" -std=c99 -O2 -Wall -Wextra -Werror \
    -I"$D2O_ROOT/datapath/include" -I"$D2O_ROOT/datapath" \
    -I"$D2O_ROOT/core/include" -I"$D2O_ROOT/core" \
    -o "$TEMP/d2o-sched" \
    "$ROOT/crates/r2o-datapath/tests/d2o_sched_differential.c" \
    "$D2O_ROOT/datapath/sched.c"
"$TEMP/d2o-sched" >"$TEMP/c.out"

"$CARGO" run --manifest-path "$ROOT/Cargo.toml" --locked --offline \
    -q -p r2o-datapath --example d21_sched_trace >"$TEMP/rust.out"

if ! diff -u "$TEMP/c.out" "$TEMP/rust.out"; then
    printf 'FAIL: scheduler differential\n' >&2
    exit 1
fi

printf 'cases=%s\n' "$(wc -l < "$TEMP/c.out")"
grep '^owned pop id=7 ' "$TEMP/c.out"
printf 'PASS: C/Rust scheduler due order, refusals and owned IDs match (D2O %s)\n' \
    "$ACTUAL_D2O_SHA"
