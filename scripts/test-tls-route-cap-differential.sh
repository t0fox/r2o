#!/bin/sh
# C/Rust differential: tls_route_segment_cap (datapath/d2kd.c:123-151).
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
TEMP=$(mktemp -d "$TMPDIR/r2o-tls-route-cap.XXXXXX")
trap 'rm -rf -- "$TEMP"' EXIT HUP INT TERM

"$CC" -std=c99 -D_GNU_SOURCE -O2 -Wall -Wextra -Werror \
    -ffunction-sections -fdata-sections -Wl,--gc-sections \
    -I"$D2O_ROOT/datapath" -I"$D2O_ROOT/datapath/include" \
    -I"$D2O_ROOT/core/include" -I"$D2O_ROOT/runtime" \
    -DD2K_RELEASE_ID='"dev"' \
    -o "$TEMP/d2o-tls-route-cap" \
    "$ROOT/crates/r2o-datapath/tests/d2o_tls_route_cap_differential.c" \
    -pthread -lm
"$TEMP/d2o-tls-route-cap" >"$TEMP/c.out"

"$CARGO" test --manifest-path "$ROOT/Cargo.toml" --locked --offline \
    -p r2o-datapath --lib raw::tls_route_cap_tests::d2o_tls_route_cap_trace \
    -- --ignored --nocapture >"$TEMP/rust.raw" 2>&1
grep -E '^[A-N] ' "$TEMP/rust.raw" >"$TEMP/rust.out"

diff -u "$TEMP/c.out" "$TEMP/rust.out"
printf 'cases=%s\n' "$(wc -l < "$TEMP/c.out")"
printf 'PASS: C/Rust tls_route_segment_cap match (D2O %s)\n' "$ACTUAL_D2O_SHA"
