#!/bin/sh
# C/Rust differential: d2k_httpsearch_save/load (формат d2k-http-plans 1).
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
TEMP=$(mktemp -d "$TMPDIR/r2o-hs-persist.XXXXXX")
trap 'rm -rf -- "$TEMP"' EXIT HUP INT TERM
mkdir -p "$TEMP/c" "$TEMP/rust"

"$CC" -std=gnu11 -O2 -Wall -Wextra -Werror -ffunction-sections -fdata-sections \
    -I"$D2O_ROOT/core" -I"$D2O_ROOT/core/include" -I"$D2O_ROOT/datapath/include" \
    -o "$TEMP/d2o-hs-persist" \
    "$ROOT/crates/r2o-controller/tests/d2o_http_plans_persist_differential.c" \
    -Wl,--gc-sections -lpthread
"$TEMP/d2o-hs-persist" "$TEMP/c" >"$TEMP/c.out"

"$CARGO" run --manifest-path "$ROOT/Cargo.toml" --locked --offline \
    -q -p r2o-controller --example http_search_persist_trace \
    -- "$TEMP/rust" >"$TEMP/rust.out"

if ! diff -u "$TEMP/c.out" "$TEMP/rust.out"; then
    printf 'FAIL: httpsearch save/load differential\n' >&2
    exit 1
fi

printf 'cases=%s\n' "$(grep -c ' rc=' "$TEMP/c.out")"
printf 'PASS: C/Rust d2k-http-plans save/load match (D2O %s)\n' "$ACTUAL_D2O_SHA"
