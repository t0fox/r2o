#!/bin/sh
# C/Rust differential: точные байты 307/RST из `build` (http80.c:156-188),
# IPv4 и IPv6. Бренд X-D2K/X-R2O нормализуется в Rust-тесте.
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

make -s -C "$D2O_ROOT/datapath" http80.o wire.o core_httpup_logic.o >/dev/null
mkdir -p "$TMPDIR"
TEMP=$(mktemp -d "$TMPDIR/r2o-http80-swap-bytes.XXXXXX")
trap 'rm -rf -- "$TEMP"' EXIT HUP INT TERM

"$CC" -std=c99 -O2 -Wall -Wextra -Werror \
    -I"$D2O_ROOT/datapath/include" -I"$D2O_ROOT/datapath" \
    -I"$D2O_ROOT/core/include" -I"$D2O_ROOT/core" \
    -o "$TEMP/d2o-http80-swap-bytes" \
    "$ROOT/crates/r2o-datapath/tests/d2o_http80_swap_bytes_differential.c" \
    "$D2O_ROOT/datapath/http80.o" "$D2O_ROOT/datapath/wire.o" \
    "$D2O_ROOT/datapath/core_httpup_logic.o"
"$TEMP/d2o-http80-swap-bytes" >"$TEMP/c.out"

R2O_HTTP80_SWAP_BYTES_OUTPUT="$TEMP/rust.out" \
    "$CARGO" test --manifest-path "$ROOT/Cargo.toml" --locked --offline \
    -p r2o-datapath --lib http_replace::tests::swap_bytes_differential_matches_c \
    -- --exact >"$TEMP/cargo.log" 2>&1

diff -u "$TEMP/c.out" "$TEMP/rust.out"
printf 'lines=%s\n' "$(wc -l <"$TEMP/c.out")"
printf 'PASS: HTTP/80 307/RST wire bytes C/Rust match, IPv4+IPv6 (D2O %s)\n' "$ACTUAL_D2O_SHA"
