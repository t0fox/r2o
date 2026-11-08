#!/bin/sh
# D17: paired C/Rust differential HTTP/80 replacement.
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
TEMP=$(mktemp -d "$TMPDIR/r2o-d17-http80.XXXXXX")
trap 'rm -rf -- "$TEMP"' EXIT HUP INT TERM

make -C "$D2O_ROOT/datapath" http80.o wire.o core_httpup_logic.o >/dev/null
"$CC" -std=c99 -O2 -Wall -Wextra -Werror \
    -I"$D2O_ROOT/datapath/include" -I"$D2O_ROOT/datapath" \
    -I"$D2O_ROOT/core/include" -I"$D2O_ROOT/core" \
    -o "$TEMP/d2o-http80" \
    "$ROOT/crates/r2o-datapath/tests/d2o_http80_differential.c" \
    "$D2O_ROOT/datapath/http80.o" \
    "$D2O_ROOT/datapath/wire.o" \
    "$D2O_ROOT/datapath/core_httpup_logic.o"
"$TEMP/d2o-http80" >"$TEMP/c.out"

"$CARGO" test --manifest-path "$ROOT/Cargo.toml" --locked --offline \
    -p r2o-datapath --lib hold::tests::d17_http80_trace \
    -- --ignored --nocapture >"$TEMP/rust.raw" 2>&1
grep -E '^D17 ' "$TEMP/rust.raw" >"$TEMP/rust.out"

if ! diff -u "$TEMP/c.out" "$TEMP/rust.out"; then
    printf 'FAIL: HTTP/80 replacement differential\n' >&2
    exit 1
fi

printf 'cases=%s\n' "$(wc -l < "$TEMP/c.out")"
grep '^D17 https ' "$TEMP/c.out"
printf 'PASS: C/Rust HTTP/80 replacement decisions match (D2O %s)\n' "$ACTUAL_D2O_SHA"
