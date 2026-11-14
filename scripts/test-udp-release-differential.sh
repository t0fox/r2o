#!/bin/sh
# C/Rust differential: d2k_udp_out_batch / release_batch —
# success/busy/permanent/tail-verdict-fail/head-verdict-fail/ENOSPC.
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
TEMP=$(mktemp -d "$TMPDIR/r2o-udp-release.XXXXXX")
trap 'rm -rf -- "$TEMP"' EXIT HUP INT TERM

"$CC" -std=c99 -O2 -Wall -Wextra -Werror \
    -I"$D2O_ROOT/datapath/include" -I"$D2O_ROOT/datapath" \
    -I"$D2O_ROOT/core/include" \
    -o "$TEMP/d2o-udp-release" \
    "$ROOT/crates/r2o-datapath/tests/d2o_udp_release_differential.c" \
    "$D2O_ROOT/datapath/udp_release.c"
"$TEMP/d2o-udp-release" >"$TEMP/c.out"

"$CARGO" test --manifest-path "$ROOT/Cargo.toml" --locked --offline \
    -p r2o-datapath --lib r2o_udp_hold::tests::d2o_udp_release_trace \
    -- --ignored --nocapture >"$TEMP/rust.raw" 2>&1
grep -E '^[A-F] ' "$TEMP/rust.raw" >"$TEMP/rust.out"

if ! diff -u "$TEMP/c.out" "$TEMP/rust.out"; then
    printf 'FAIL: C/Rust UDP release batch differential\n' >&2
    exit 1
fi
printf 'cases=%s\n' "$(wc -l < "$TEMP/c.out")"
printf 'PASS: C/Rust UDP release batch match (D2O %s)\n' "$ACTUAL_D2O_SHA"
