#!/bin/sh
# C/Rust differential: parse_ip (datapath/icmpguard.c:21-47).
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
TEMP=$(mktemp -d "$TMPDIR/r2o-parse-ip.XXXXXX")
trap 'rm -rf -- "$TEMP"' EXIT HUP INT TERM

"$CC" -std=c99 -O2 -Wall -Wextra -Werror \
    -ffunction-sections -fdata-sections -Wl,--gc-sections \
    -I"$D2O_ROOT/datapath" -I"$D2O_ROOT/datapath/include" \
    -o "$TEMP/d2o-parse-ip" \
    "$ROOT/crates/r2o-datapath/tests/d2o_parse_ip_differential.c"
"$TEMP/d2o-parse-ip" >"$TEMP/c.out"

"$CARGO" test --manifest-path "$ROOT/Cargo.toml" --locked --offline \
    -p r2o-datapath --lib r2o_icmp_guard::tests::d2o_parse_ip_trace \
    -- --ignored --nocapture >"$TEMP/rust.raw" 2>&1
grep -E '^[A-O] ' "$TEMP/rust.raw" >"$TEMP/rust.out"

diff -u "$TEMP/c.out" "$TEMP/rust.out"
printf 'cases=%s\n' "$(wc -l < "$TEMP/c.out")"
printf 'PASS: C/Rust parse_ip quote match (D2O %s)\n' "$ACTUAL_D2O_SHA"
