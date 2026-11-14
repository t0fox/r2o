#!/bin/sh
# C/Rust differential: request_feed (datapath/http80.c:342-347).
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
TEMP=$(mktemp -d "$TMPDIR/r2o-request-feed.XXXXXX")
trap 'rm -rf -- "$TEMP"' EXIT HUP INT TERM

"$CC" -std=c99 -D_GNU_SOURCE -O2 -Wall -Wextra -Werror \
    -I"$D2O_ROOT/datapath" -I"$D2O_ROOT/datapath/include" \
    -I"$D2O_ROOT/core/include" -ffunction-sections -fdata-sections \
    -o "$TEMP/d2o-request-feed" \
    "$ROOT/crates/r2o-datapath/tests/d2o_request_feed_differential.c" \
    -Wl,--gc-sections
"$TEMP/d2o-request-feed" >"$TEMP/c.out"

R2O_REQUEST_FEED_DIFF_OUTPUT="$TEMP/rust.out" \
    "$CARGO" test --manifest-path "$ROOT/Cargo.toml" --locked --offline \
    -p r2k-core --test httpup request_feed_differential_matches_c \
    -- --exact >"$TEMP/cargo.log" 2>&1

diff -u "$TEMP/c.out" "$TEMP/rust.out"
printf 'cases=%s\n' "$(wc -l <"$TEMP/c.out")"
printf 'PASS: request_feed C/Rust match (D2O %s)\n' "$ACTUAL_D2O_SHA"
