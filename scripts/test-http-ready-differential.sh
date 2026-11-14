#!/bin/sh
# C/Rust differential: http_ready (datapath/hold.c:93-100).
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
make -s -C "$DENY" http80.o core_httpup_logic.o CC="$CC" >/dev/null
mkdir -p "$TMPDIR"
TEMP=$(mktemp -d "$TMPDIR/r2o-http-ready.XXXXXX")
trap 'rm -rf -- "$TEMP"' EXIT HUP INT TERM

"$CC" -std=c99 -D_GNU_SOURCE -O2 -Wall -Wextra -Werror \
    -ffunction-sections -fdata-sections -Wl,--gc-sections \
    -I"$DENY" -I"$DENY/include" -I"$D2O_ROOT/core/include" \
    -o "$TEMP/d2o-http-ready" \
    "$ROOT/crates/r2o-datapath/tests/d2o_http_ready_differential.c" \
    "$DENY/http80.o" "$DENY/core_httpup_logic.o"
"$TEMP/d2o-http-ready" >"$TEMP/c.out"

"$CARGO" run --manifest-path "$ROOT/Cargo.toml" --locked --offline \
    -q -p r2o-datapath --example r2o_http_ready_trace >"$TEMP/rust.out"

diff -u "$TEMP/c.out" "$TEMP/rust.out"
printf 'cases=%s\n' "$(wc -l < "$TEMP/c.out")"
printf 'PASS: C/Rust http_ready tri-state match (D2O %s)\n' "$ACTUAL_D2O_SHA"
