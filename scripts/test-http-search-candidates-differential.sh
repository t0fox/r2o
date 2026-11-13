#!/bin/sh
# C/Rust differential: CANDS/stable_id/answer_name из httpsearch.c.
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
TEMP=$(mktemp -d "$TMPDIR/r2o-hs-candidates.XXXXXX")
trap 'rm -rf -- "$TEMP"' EXIT HUP INT TERM

"$CC" -std=gnu11 -O2 -Wall -Wextra -Werror -ffunction-sections -fdata-sections \
    -I"$D2O_ROOT/core" -I"$D2O_ROOT/core/include" -I"$D2O_ROOT/datapath/include" \
    -o "$TEMP/d2o-hs-candidates" \
    "$ROOT/crates/r2o-controller/tests/d2o_http_search_candidates_differential.c" \
    -Wl,--gc-sections -lpthread
"$TEMP/d2o-hs-candidates" >"$TEMP/c.out"

"$CARGO" run --manifest-path "$ROOT/Cargo.toml" --locked --offline \
    -q -p r2o-controller --example http_search_candidates_trace >"$TEMP/rust.out"

if ! diff -u "$TEMP/c.out" "$TEMP/rust.out"; then
    printf 'FAIL: http search candidates differential\n' >&2
    exit 1
fi

printf 'cases=%s\n' "$(grep -c '^\(candidate\|stable\|answer\|count\)' "$TEMP/c.out")"
printf 'PASS: C/Rust HTTP-search candidates, stable id and answer names match (D2O %s)\n' "$ACTUAL_D2O_SHA"
