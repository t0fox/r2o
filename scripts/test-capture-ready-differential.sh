#!/bin/sh
# C/Rust differential: d2k_capture_feed (capture.c:22-124).
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

DENY="$D2O_ROOT/datapath"
make -s -C "$DENY" capture.o track.o >/dev/null
mkdir -p "$TMPDIR"
TEMP=$(mktemp -d "$TMPDIR/r2o-capture-ready.XXXXXX")
trap 'rm -rf -- "$TEMP"' EXIT HUP INT TERM

"$CC" -std=c99 -O2 -Wall -Wextra -Werror \
    -I"$DENY/include" -I"$D2O_ROOT/core/include" \
    -o "$TEMP/d2o-capture-ready" \
    "$ROOT/crates/r2o-datapath/tests/d2o_capture_ready_differential.c" \
    "$DENY/capture.o" "$DENY/track.o"
"$TEMP/d2o-capture-ready" >"$TEMP/c.out"

"$CARGO" test --manifest-path "$ROOT/Cargo.toml" --locked --offline \
    -p r2o-datapath --lib capture::tests::d2o_capture_ready_trace \
    -- --ignored --nocapture >"$TEMP/rust.raw" 2>&1
grep -E '^([A-K]) ' "$TEMP/rust.raw" >"$TEMP/rust.out"

diff -u "$TEMP/c.out" "$TEMP/rust.out"
printf 'cases=%s\n' "$(wc -l < "$TEMP/c.out")"
printf 'PASS: C/Rust d2k_capture_feed TLS capture match (D2O %s)\n' "$ACTUAL_D2O_SHA"
