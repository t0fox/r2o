#!/bin/sh
# C/Rust differential: tcp_watch (datapath/session.c:3257-3261).
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
TEMP=$(mktemp -d "$TMPDIR/r2o-tcp-watch.XXXXXX")
trap 'rm -rf -- "$TEMP"' EXIT HUP INT TERM

"$CC" -std=c99 -D_GNU_SOURCE -O2 -Wall -Wextra \
    -ffunction-sections -fdata-sections -Wl,--gc-sections \
    -I"$D2O_ROOT/datapath" -I"$D2O_ROOT/datapath/include" \
    -I"$D2O_ROOT/core/include" -I"$D2O_ROOT/runtime" \
    -o "$TEMP/d2o-tcp-watch" \
    "$ROOT/crates/r2o-datapath/tests/d2o_tcp_watch_differential.c" -lm
"$TEMP/d2o-tcp-watch" >"$TEMP/c.out"

"$CARGO" test --manifest-path "$ROOT/Cargo.toml" --locked --offline \
    -p r2o-datapath --lib engine::tests::d2o_tcp_watch_trace \
    -- --ignored --nocapture >"$TEMP/rust.raw" 2>&1
grep -E '^case=' "$TEMP/rust.raw" >"$TEMP/rust.out"

diff -u "$TEMP/c.out" "$TEMP/rust.out"
printf 'cases=%s\n' "$(wc -l < "$TEMP/c.out")"
printf 'PASS: C/Rust tcp_watch candidate set match (D2O %s)\n' "$ACTUAL_D2O_SHA"
